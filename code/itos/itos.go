// itos is short for "identifying targeted onion services."  It takes as input
// a set of onion services and malicious HSDirs, and tries to figure out what
// onion services the HSDirs targeted, by calculating descriptor IDs.
//
// Copyright 2017 Philipp Winter <phw@nymity.ch>
//
// itos is free software: you can redistribute it and/or modify it under the
// terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// itos is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License along with
// itos.  If not, see <http://www.gnu.org/licenses/>.
package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base32"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	SimThreshold = 5     // Just a hunch, for now.
	SecsPerDay   = 86400 // Not a hunch.
	Start        = 0
	End          = 1
)

// Replicas represents the two numerals that are used to replicate descriptors
// across Tor's hash ring.
var Replicas = []byte{0, 1}

// AttackedHSes keeps track of onion services that might have been targeted.
var AttackedHSes = make(map[string]struct{})

// getTime turns the given Tor-specific, four-byte time period into a
// human-readable string.  That helps in figuring out when a malicious HSDir
// targeted a particular descriptor ID.
func getTime(timePeriod [4]uint8) string {

	var t uint32

	t = uint32(timePeriod[3])
	t |= uint32(timePeriod[2]) << 8
	t |= uint32(timePeriod[1]) << 16
	t |= uint32(timePeriod[0]) << 24

	return fmt.Sprintf("%s", time.Unix(int64(t*SecsPerDay-SecsPerDay), 0))
}

// min returns the smaller of the two given values.
func min(len1, len2 int) int {

	if len1 < len2 {
		return len1
	} else {
		return len2
	}
}

// similarity quantifies the distance between a given descriptor ID and HSDir
// ID.  The intuition is that the higher the similarity, the more likely that
// the given HSDir was targeting the descriptor.
func similarity(HSDirId, descriptorId string) int {

	descriptorId = strings.ToLower(descriptorId)
	HSDirId = strings.ToLower(HSDirId)

	// If HSDir < descriptorId, there's no way it's the attacker.
	if strings.Compare(HSDirId, descriptorId) == -1 {
		return 0
	}

	length := min(len(descriptorId), len(HSDirId))
	for i := 0; i < length; i++ {
		if descriptorId[i] != HSDirId[i] {
			return i
		}
	}
	return length
}

// isNastyHSDir attempts to find HSDirs that could have attacked the given
// descriptor ID.  We do that by checking if the fingerprint prefix exceeds or
// is equal to our threshold.
func isNastyHSDir(HSDirId, descriptorId, onionService string, timePeriod [4]uint8) bool {

	// Check if descriptor ID is similar to any of our malicious HSDirs.
	if similarity(HSDirId, descriptorId) >= SimThreshold {
		fmt.Printf("%s,%s,%s,%s\n", HSDirId, descriptorId,
			strings.ToLower(onionService), getTime(timePeriod))
		AttackedHSes[onionService] = struct{}{}
		return true
	}

	return false
}

// parseHSDirs parses the given CSV file and returns a map that maps relay
// fingerprints to an array that contains the time stamps indicating when the
// relay was first and last online, respectively.
func parseHSDirs(file string) map[string][2]int {

	HSDirs := make(map[string][2]int)

	fd, err := os.Open(file)
	if err != nil {
		log.Fatalf("Couldn't open HSDirs file because: %s\n", err)
	}
	defer fd.Close()

	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		line := scanner.Text()
		words := strings.Split(line, ",")
		n1, n2 := strToInt(words[1]), strToInt(words[2])
		if n1 > n2 {
			log.Fatalf("Relay %s: %d cannot be larger than %d.\n", words[0], n1, n2)
		}
		HSDirs[words[0]] = [2]int{n1, n2}
	}

	return HSDirs
}

// parseHSs parses the given file and returns a slice of onion services.
func parseHSs(file string) []string {

	var HSs []string

	fd, err := os.Open(file)
	if err != nil {
		log.Fatalf("Couldn't open HSs file because: %s\n", err)
	}
	defer fd.Close()

	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		line := scanner.Text()
		HSs = append(HSs, line)
	}

	return HSs
}

// strToInt converts the given string to an integer.
func strToInt(num string) int {

	i, err := strconv.Atoi(num)
	if err != nil {
		log.Fatalf("Couldn't convert string to integer because: %s\n", err)
	}

	return i
}

// iterateHSs iterates over the given onion services and checks if any of the
// given HSDirs could have attacked an onion service.  The function returns a
// list of HSDirs whose fingerprint is suspiciously close (the threshold is
// determined by SimThreshold) to any onion service's descriptor ID.
func iterateHSs(HSDirs map[string][2]int, HSs []string) []string {

	var nastyHSDirs []string
	var descriptorId string
	var timePeriod [4]uint8
	// The two most significant bytes (in network byte order) never change.
	timePeriod[0] = 0
	timePeriod[1] = 0

	// CSV header.
	fmt.Println("hsdir,desc,onionservice,time")

	allServices := len(HSs)
	// Iterate over all onion services we have.  Any of them could be a victim.
	for i, onionService := range HSs {

		if (i+1)%100 == 0 {
			log.Printf("Processing %d/%d onion services.\n", i+1, allServices)
		}

		// Turn onion service string into byte array.
		permanentId, err := base32.StdEncoding.DecodeString(onionService)
		if err != nil {
			log.Printf("Failed to decode %s because: %s\n", onionService, err)
			continue
		}

		for HSDirId, timePeriods := range HSDirs {

			// Iterate over time-period values when HSDir was online.
			for i := timePeriods[Start]; i <= timePeriods[End]; i++ {

				timePeriod[2] = uint8(i >> 8)
				timePeriod[3] = uint8(i % 256)

				for _, replica := range Replicas {

					// secret-id-part = H(time-period | descriptor-cookie | replica)
					// Descriptor cookies are not used in practice, so we only hash
					// time-period and replica.
					secretIdPart := sha1.Sum(append(timePeriod[:], replica))
					descriptorIdRaw := sha1.Sum(append(permanentId, secretIdPart[:]...))
					descriptorId = hex.EncodeToString(descriptorIdRaw[:])

					if isNastyHSDir(HSDirId, descriptorId, onionService, timePeriod) {
						nastyHSDirs = append(nastyHSDirs, HSDirId)
					}
				}
			}
		}
	}

	log.Printf("%d out of %d HSes might have been attacked.\n",
		len(AttackedHSes), len(HSs))

	return nastyHSDirs
}

func main() {

	HSDirsFile := flag.String("hsdirs", "", "File containing malicious hidden service directories.")
	HSsFile := flag.String("hss", "", "File containing hidden services.")
	flag.Parse()

	iterateHSs(parseHSDirs(*HSDirsFile), parseHSs(*HSsFile))
}
