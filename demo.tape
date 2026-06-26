# vhs script — renders a preview of the demo to demo.gif.
#   brew install vhs   (or see https://github.com/charmbracelet/vhs)
#   vhs demo.tape
#
# Shows the run start + the AI-governance section (the centerpiece). `sed` reads
# all of stdin (no broken-pipe traceback) but only prints the first ~50 lines, so
# the gif stays small and lands on the most important output. The README/DEMO.md
# cover the remaining sections.

Output demo.gif

Set Shell "bash"
Set FontSize 13
Set Width 1100
Set Height 770
Set Theme "Catppuccin Mocha"
Set Padding 16
Set TypingSpeed 55ms

Type "python3 demo.py | sed -n '1,50p'"
Sleep 500ms
Enter
Sleep 7s
