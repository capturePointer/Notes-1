import idaapi
idaapi.CompileLine('static n_key() { RunPythonStatement("nopIt()"); }')
AddHotkey("Alt-N", "n_key")
def nopIt():
   
      start = ScreenEA()
      end = NextHead(start)
      for ea in range(start, end):
            PatchByte(ea, 0x90)
      Jump(end)
      Refresh()