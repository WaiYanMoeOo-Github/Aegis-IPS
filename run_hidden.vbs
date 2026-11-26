Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

baseDir = fso.GetParentFolderName(WScript.ScriptFullName)
pythonExe = """" & baseDir & "\venv\Scripts\python.exe"""

WshShell.CurrentDirectory = baseDir

' Start FastAPI Backend completely hidden (0 = Hidden)
WshShell.Run pythonExe & " -m uvicorn main:app --host 0.0.0.0 --port 8000", 0, False

' Wait 5 seconds for Backend to initialize
WScript.Sleep 5000

' Start Real-Time Packet Sensor completely hidden (0 = Hidden)
WshShell.Run pythonExe & " sensor.py", 0, False