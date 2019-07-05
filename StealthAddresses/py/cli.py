from cmd import Cmd
from stealth_generate import stealth_generate
from stealth_send import stealth_send

class MyPrompt(Cmd):
    prompt = 'stealth> '
    intro = "Welcome! Type ? to list commands"
    
    def do_exit(self, inp):
        '''exit the application'''
        return True
    
    def do_generate(self, inp):
        '''generate a new stealth address'''
        stealth_addr = stealth_generate(inp)

    def do_send(self, inp):
        '''sent transaction to stealth address'''
        sealth_send = stealth_send(inp.split(' '))
        print(sp)
        print(len(inp))

MyPrompt().cmdloop()
