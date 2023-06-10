package main

import (
	"archive/zip"
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

//go:embed icon.png
var windowIcon []byte

var selectedProtections []string

var sequences = [][]byte{
	{
		0x38, 0x54, 0x59, 0x04, 0x10, 0x35, 0x54, 0x59, 0x05, 0x10, 0x2E, 0x54, 0x59, 0x06, 0x10, 0x32,
		0x54, 0x59, 0x07, 0x10, 0x31, 0x54, 0x59, 0x08, 0x10, 0x37, 0x54, 0x59, 0x10, 0x06, 0x10, 0x2E,
		0x54, 0x59, 0x10, 0x07, 0x10, 0x31, 0x54, 0x59, 0x10, 0x08, 0x10, 0x34, 0x54, 0x59, 0x10, 0x09,
		0x10, 0x34, 0x54, 0x59, 0x10, 0x0A, 0x10, 0x2E, 0x54, 0x59, 0x10, 0x0B, 0x10, 0x31, 0x54, 0x59,
		0x10, 0x0C, 0x10, 0x33, 0x54, 0x59, 0x10, 0x0D, 0x10, 0x30, 0x54, 0xB7,
	},
	{
		0x68, 0x54, 0x59, 0x04, 0x10, 0x74, 0x54, 0x59, 0x05, 0x10, 0x74, 0x54, 0x59, 0x06, 0x10, 0x70,
		0x54, 0x59, 0x07, 0x10, 0x3a, 0x54, 0x59, 0x08, 0x10, 0x2f, 0x54, 0x59, 0x10, 0x06, 0x10, 0x2f,
		0x54, 0x59, 0x10, 0x07, 0x10, 0x66, 0x54, 0x59, 0x10, 0x08, 0x10, 0x69, 0x54, 0x59, 0x10, 0x09,
		0x10, 0x6c, 0x54, 0x59, 0x10, 0x0A, 0x10, 0x65, 0x54, 0x59, 0x10, 0x0B, 0x10, 0x73, 0x54, 0x59,
		0x10, 0x0C, 0x10, 0x2e, 0x54, 0x59, 0x10, 0x0a, 0x10, 0x73, 0x54, 0x59, 0x10, 0x0e, 0x10, 0x6b,
		0x54, 0x59, 0x10, 0x0f, 0x10, 0x79, 0x54, 0x59, 0x10, 0x10, 0x10, 0x72, 0x54, 0x59, 0x10, 0x11,
		0x10, 0x61, 0x54, 0x59, 0x10, 0x12, 0x10, 0x67, 0x54, 0x59, 0x10, 0x13, 0x10, 0x65, 0x54, 0x59,
		0x10, 0x14, 0x10, 0x2e, 0x54, 0x59, 0x10, 0x15, 0x10, 0x64,
	},
	{
		0x2d, 0x54, 0x59, 0x04, 0x10, 0x6a, 0x54, 0x59, 0x05, 0x10, 0x61, 0x54, 0x59, 0x06, 0x10, 0x72,
	},
}

var (
	textLabelScan = `# Welcome to Defracturaiser!
This application aims to find infected .JARs by Fractureiser and protect you from the virus.

You can find detailed [information of Fractureiser here](https://github.com/fractureiser-investigation/fractureiser#what).

---

**On this tab you can scan your computer for Stage 0, 1, 2 and 3 infection, you just need to click on the button below. You can also verify a single, for example, verifying a file you have downloaded from the internet.**

The next tab allow you to setup protection for your computer, for more details, click on the tab "Protect".`

	textLabelProtect = `# Active protection from Fractureiser
On this tab you can set protection for your computer, such as:

- Block known IPs
- Scheduled Scans

---
Here are the protections you can enable for your computer:`

	textLabelAbout = `# About Defracturaiser
Made in Golang by Princess Mortix using the Fyne toolkit.

## Credits
- [Everyone at Fractureiser investigation](https://github.com/fractureiser-investigation/fractureiser/blob/main/docs/credits.md): Y'all deserve the best <3;
- [MCRcortex](https://github.com/MCRcortex/nekodetector): Made the first detector in java, which was the reason I started my version;
- [IridiumIO](https://github.com/IridiumIO/Anti-Fractureiser): Also made a detector, which I inspired protections from their project;
- [UniIcons](https://iconscout.com/unicons/explore/line): the virus icon on the logo;
- You, for using this application.`
)

type TextGridWriter struct {
	TextGridWidget *widget.TextGrid
}

func (tw *TextGridWriter) Write(p []byte) (n int, err error) {
	// Convert the byte slice to string
	logMsg := string(p)

	// Update the TextGrid widget with the log message
	tw.TextGridWidget.SetText(tw.TextGridWidget.Text() + logMsg)

	return len(p), nil
}

func main() {
	slashFractureiser := app.NewWithID("link.princessmortix.defracturaiser")
	mainSlashFractureiserWindow := slashFractureiser.NewWindow("Defracturaiser")
	mainSlashFractureiserWindow.Resize(fyne.NewSize(800, 600))
	mainSlashFractureiserWindow.SetTitle("Defracturaiser - Scan for Fractureiser in your computer")
	mainSlashFractureiserWindow.SetIcon(&fyne.StaticResource{StaticName: "Icon", StaticContent: windowIcon})

	//UI code of the first tab: Scan
	labelTabScanVerify := widget.NewRichTextFromMarkdown(textLabelScan)
	labelTabScanVerify.Wrapping = fyne.TextWrapWord

	progressTabScan := widget.NewProgressBarInfinite()
	progressTabScan.Hide() // Why is the progress bar here?
	//Because I need to declare it first to edit it on the button later.

	logsTabScan := widget.NewTextGrid()
	scrollLogsTabScanContainer := container.NewScroll(logsTabScan)
	scrollLogsTabScanContainer.SetMinSize(fyne.NewSize(800, 300))

	buttonTabScanVerify := widget.Button{
		Text: "Scan my computer",
		Icon: theme.SearchIcon(),
		OnTapped: func() {
			dialogScanAdmin := dialog.NewInformation("Requested full system scan", "We will now begin scanning your system to find Fractureiser, should take less than 5 minutes.\nWe recommend running the applcation as administrador for a full scan.", mainSlashFractureiserWindow)
			dialogScanAdmin.SetOnClosed(func() {
				progressTabScan.Show()
				progressTabScan.Start()

				skippedFiles, infetedFiles, timeTaken, err := scan(logsTabScan)
				if err != nil {
					dialog.ShowError(errors.New("Could not scan your device due of the following error: "+err.Error()), mainSlashFractureiserWindow)
					return
				}

				if len(infetedFiles) > 0 {
					infetedFilesList := strings.Join(infetedFiles, "\n")
					dialog.ShowConfirm("Infected files found!", "The following file(s) are infected: "+infetedFilesList+".\nDo you want to remove them now?", func(removeFiles bool) {
						if removeFiles {
							for _, files := range infetedFiles {
								err := os.Remove(files)
								if err != nil {
									dialog.ShowError(errors.New("Could not delete the file "+files+" You should manually delete the file."), mainSlashFractureiserWindow)
									return
								}
							}
						}
					}, mainSlashFractureiserWindow)
				} else {
					skippedFilesList := strings.Join(skippedFiles, ", ")
					dialog.ShowInformation("Scan finished!", "Skipped files: "+skippedFilesList+". Time taken: "+timeTaken.String(), mainSlashFractureiserWindow)
				}
				infection, err := stage1and2Scan(logsTabScan)
				if infection {
					dialog.ShowInformation("Infection for stage 1 and/or 2 found!", "You're likely infected by the virus.\nWe recommend changing all your passwords, creating new credit card info and disabling your old one.", mainSlashFractureiserWindow)
				}
				if err != nil {
					log.Println(err)
				}
				progressTabScan.Stop()
				progressTabScan.Hide()
			})
			dialogScanAdmin.Show()
		},
	}
	buttonTabScanVerifySingle := widget.Button{
		Text: "Verify single file",
		Icon: theme.FileApplicationIcon(),
		OnTapped: func() {
			//Verifies a single file
			dialogTabScanVerifySingle := dialog.NewFileOpen(func(selectedFile fyne.URIReadCloser, err error) {
				if err != nil {
					log.Println("File dialog error:", err)
					return
				}

				if selectedFile == nil {
					dialog.ShowError(errors.New("No file selected."), mainSlashFractureiserWindow)
					log.Println("No file selected")
					return
				}

				selectedFilePath := selectedFile.URI().Path()
				log.Println("Selected file:", selectedFilePath)

				scanResult, err := scanFile(selectedFilePath)
				if err != nil {
					log.Fatalln(err)
				}

				if scanResult {
					dialog.ShowConfirm("The file is infected.", "The file at "+selectedFilePath+" is infected.\nDo you want to delete this file?", func(deleteFile bool) {
						if deleteFile {
							err := os.Remove(selectedFilePath)
							if err != nil {
								dialog.ShowError(errors.New("Could not delete the file at "+selectedFilePath+" You should manually delete the file."), mainSlashFractureiserWindow)
								return
							}
							dialog.ShowInformation("Sucess!", selectedFilePath+" was sucessfully deleted.", mainSlashFractureiserWindow)
						}
					}, mainSlashFractureiserWindow)
				} else {
					dialog.ShowInformation("File is clean", "The file you provided is clean. Note that it can be also a false-positive.", mainSlashFractureiserWindow)
				}

			}, mainSlashFractureiserWindow)
			dialogTabScanVerifySingle.SetFilter(storage.NewExtensionFileFilter([]string{".jar"}))
			dialogTabScanVerifySingle.Resize(fyne.Size{
				Width:  800,
				Height: 600,
			})
			dialogTabScanVerifySingle.Show()
		},
	}
	separatorTabScan := widget.NewSeparator()

	contentTabScanNoLog := container.New(layout.NewVBoxLayout(), labelTabScanVerify, &buttonTabScanVerify, &buttonTabScanVerifySingle, separatorTabScan, progressTabScan)
	//contentTabScanLog := container.NewVScroll(logsTabScan)
	contentTabScan := container.New(layout.NewVBoxLayout(), contentTabScanNoLog, scrollLogsTabScanContainer)

	// End of the Tab scan content.

	//UI code of the secound tab: Protect
	labelTabProtect := widget.NewRichTextFromMarkdown(textLabelProtect)
	labelTabProtect.Wrapping = fyne.TextWrapWord
	optionsTabProtect := widget.CheckGroup{
		Horizontal: true,
		Options:    []string{"Block Known IPs", "Schedule Scans"},
		Selected:   selectedProtections,
		OnChanged: func(s []string) {
			//Change protections
			log.Println(selectedProtections) //Will be added soon
		},
	}
	contentTabProtect := container.New(layout.NewVBoxLayout(), labelTabProtect, &optionsTabProtect)
	//End of the Protect Tab code

	//UI code of the last tab: About
	labelTabAbout := widget.NewRichTextFromMarkdown(textLabelAbout)
	labelTabAbout.Wrapping = fyne.TextWrapWord
	buttonFractureiserTabAbout := widget.Button{
		Text: "View the Fractureiser investigation in GitHub",
		Icon: theme.ComputerIcon(),
		OnTapped: func() {
			slashFractureiser.OpenURL(parseUrl("https://github.com/fractureiser-investigation/fractureiser"))
		}, //Little hacky, but works
	}
	buttonGhTabAbout := widget.Button{
		Text: "View this project page in GitHub",
		Icon: theme.ComputerIcon(),
		OnTapped: func() {
			slashFractureiser.OpenURL(parseUrl("https://github.com/princessmortix/unfractureiser"))
		},
	}
	contentTabAbout := container.New(layout.NewVBoxLayout(), labelTabAbout, &buttonFractureiserTabAbout, &buttonGhTabAbout)
	//End.

	tabsMainContent := container.NewAppTabs(
		container.NewTabItemWithIcon("Scan", theme.SearchIcon(), contentTabScan),
		container.NewTabItemWithIcon("Protect", theme.ComputerIcon(), contentTabProtect),
		container.NewTabItemWithIcon("About", theme.InfoIcon(), contentTabAbout),
	)
	mainSlashFractureiserWindow.SetContent(tabsMainContent)
	mainSlashFractureiserWindow.Show()
	slashFractureiser.Run()
}

func parseUrl(link string) *url.URL {
	parseLink, _ := url.Parse(link)
	return parseLink
}

func scan(textGridWidget *widget.TextGrid) ([]string, []string, time.Duration, error) { //This function scans all the disks.
	textGridWidgetWriter := &TextGridWriter{TextGridWidget: textGridWidget}
	log.SetOutput(textGridWidgetWriter)
	log.Println("[*] Scanning all drives...")
	start := time.Now()

	skippedFiles := make([]string, 0)
	infectedFiles := make([]string, 0)

	// Get all drives in the system
	driveLetters, err := getDriveLetters()
	if err != nil {
		return nil, nil, 0, err
	}

	// Read all disks
	for _, driveLetter := range driveLetters {
		rootDir := driveLetter + ":\\" // Root dir from disk
		log.Printf("[*] Started scanning drive %s:", driveLetter)

		err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				fmt.Printf("Error accessing %s: %v\n", path, err)
				skippedFiles = append(skippedFiles, path)
				return nil
			}

			if info.IsDir() {
				// Ignore protected read-only paths
				if strings.Contains(path, "$Recycle.Bin") || strings.Contains(path, "Windows Defender Advanced Threat Protection") || strings.Contains(path, "System Volume Information") {
					skippedFiles = append(skippedFiles, path)
					return filepath.SkipDir
				}
				return nil
			}

			if filepath.Ext(path) == ".jar" {
				err := checkFile(path, &infectedFiles)
				if err != nil {
					log.Println(err)
					skippedFiles = append(skippedFiles, path)
				}
			}

			return nil
		})

		if err != nil {
			return nil, nil, 0, err
		}
		log.Printf("[i] The drive %s: has finished scanning.\n", driveLetter)
	}

	timeTaken := time.Since(start)
	log.Println("[*] Finished scanning.")
	log.Println("[*] Time taken:", timeTaken)
	return skippedFiles, infectedFiles, timeTaken, nil
}

func scanFile(file string) (bool, error) { //This scans a single file, returns true if something is infected.
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return false, err
	}

	reader := bytes.NewReader(data)
	archive, err := zip.NewReader(reader, int64(len(data)))
	if err != nil {
		return false, err
	}

	for _, file := range archive.File {
		if file.FileInfo().IsDir() || filepath.Ext(file.Name) != ".class" {
			continue
		}

		classFile, err := file.Open()
		if err != nil {
			return false, err
		}
		defer classFile.Close()

		content, err := ioutil.ReadAll(classFile)
		if err != nil {
			return false, err
		}

		if containsSequence(content) {
			return true, nil
		}
		classFile.Close()
	}

	return false, nil
}

func checkFile(file string, infectedFiles *[]string) error {
	fileName := filepath.Base(file)
	fmt.Printf("Checking %s\n", fileName)

	data, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}

	reader := bytes.NewReader(data)
	archive, err := zip.NewReader(reader, int64(len(data)))
	if err != nil {
		return err
	}

	isInfected := false

	for _, file := range archive.File {
		if file.FileInfo().IsDir() || filepath.Ext(file.Name) != ".class" {
			continue
		}

		classFile, err := file.Open()
		if err != nil {
			return err
		}
		defer classFile.Close()

		content, err := ioutil.ReadAll(classFile)
		if err != nil {
			return err
		}

		if containsSequence(content) {
			isInfected = true
			break
		}
		classFile.Close()
	}

	if isInfected {
		log.Printf("[!] %s is infected!\n", fileName)
		*infectedFiles = append(*infectedFiles, file)
		return nil
	}

	return nil
}

func containsSequence(content []byte) bool {
	for _, sequence := range sequences {
		if bytes.Contains(content, sequence) {
			return true
		}
	}
	return false
}

func getDriveLetters() ([]string, error) {
	driveLetters := make([]string, 0)

	// Scans all disks from A: to Z:
	for letter := 'A'; letter <= 'Z'; letter++ {
		drive := string(letter) + ":\\"
		_, err := os.Open(drive)
		if err == nil {
			driveLetters = append(driveLetters, string(letter))
		}
	}

	return driveLetters, nil
}

func stage1and2Scan(textGridWidget *widget.TextGrid) (bool, error) {
	textGridWidgetWriter := &TextGridWriter{TextGridWidget: textGridWidget}
	log.SetOutput(textGridWidgetWriter)
	log.Println("[i] Stage 1/2 scan started. Scanning for malware files on the user folder, startup and registry...")

	userHome, _ := os.UserHomeDir()
	pathEdge := filepath.Join(userHome, "AppData", "Local", "Microsoft Edge")
	log.Println("[*] Searching for", pathEdge)
	if dirEdgeAppdata, err := os.Stat(pathEdge); err == nil && dirEdgeAppdata.IsDir() {
		log.Println("[!] The folder exists! You're likely infected")
		return true, nil
	}

	startupPath := filepath.Join(userHome, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "run.bat")
	log.Println("[*] Searching for", startupPath)
	_, err := os.Stat(startupPath)
	if err == nil {
		log.Println("[!] run.bat exists! You're likely infected")
		return true, nil
	}

	log.Println("[*] Your system looks like clean from infection stage 1 and 2")
	return false, nil
}
