import Command

@Command.CommandFunction()
def Command(*Arguments):
    print("You've passed me:", ", ".join(Arguments))
    