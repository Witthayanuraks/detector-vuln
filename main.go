package main

import (
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

func main() {
	a := app.New()
	w := a.NewWindow("Detector Vuln")

	label := widget.NewLabel("Hello, Fyne!")
	w.SetContent(container.NewVBox(
		label,
		widget.NewButton("Klik aku", func() {
			label.SetText("Tombol diklik!")
		}),
	))

	w.ShowAndRun()
}
