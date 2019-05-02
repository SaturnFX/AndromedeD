import Command
import ReCALL

@Command.CommandFunction()
def Command(*Arguments):
	print("import recall")
	dir(ReCALL)
    