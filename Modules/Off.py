import Command

@Command.CommandFunction
def Command(*Arguments):
    print(Arguments)
    