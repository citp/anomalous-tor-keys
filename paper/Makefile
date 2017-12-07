TARGET=main
all: pdf

pdf:
	GS_OPTIONS=-dPDFSETTINGS=/prepress rubber -f --pdf -Wrefs -Wmisc $(TARGET)

clean:
	@rubber --clean --pdf $(TARGET)

ps: pdf
	GS_OPTIONS=-dPDFSETTINGS=/prepress pdftops -level1 $(TARGET).pdf
