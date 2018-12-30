import Command

@Command.CommandFunction()
def Command(*Arguments):
	print("I'm throwing now!")
	raise SampleError("This is the message")
	
class SampleError(Exception):
	pass
