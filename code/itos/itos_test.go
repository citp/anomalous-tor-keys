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
	"testing"
)

func TestDescriptorDerivation(t *testing.T) {

	// Six HSDirs.  Four are attacking the onion service, according to our
	// threshold.
	HSDirs := map[string][2]int{
		// Descriptor ID: 31F1E5E501608D144A48EA5F49079E8A61FC3E18
		"31F1E5F9EDD602517A8BDD24032529F0DE431AAF": [2]int{17239, 17239},
		"31F1E5F22F034B5F682EDE472CA6E3088DA27E5D": [2]int{17239, 17239},
		"31F1A5FF4887230B0767F54BA08A450B68D777F2": [2]int{17239, 17239},

		// Descriptor ID: 9AF82226CFB777531403F5A3D9BFF8751ED04FE7
		"9AF8225B3B8A9B82FA7DC1C6B34471D792F37818": [2]int{17239, 17239},
		"9AF8227A68FC036B96A253B8A9599EE611490164": [2]int{17239, 17239},
		"9AF812DF59D916E990CA52F233087499CAEAA038": [2]int{17239, 17239},
	}
	HSs := []string{"AOPXFDVTE2QFATD2"}

	nastyHSDirs := iterateHSs(HSDirs, HSs)
	if len(nastyHSDirs) != (len(HSDirs) - 2) {
		t.Errorf("Incorrect number of attacking HSDirs (%d instead of %d).",
			len(nastyHSDirs), len(HSDirs))
	}
}
