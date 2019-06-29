from cmd import Cmd
from stealth_generate import stealth_generate

class MyPrompt(Cmd):
    prompt = 'stealth> '
    intro = "Welcome! Type ? to list commands"
    
    def do_exit(self, inp):
        '''exit the application'''
        return True
    
    def do_generate(self, inp):
        '''generate a new stealth address'''
        assert(type(inp) == str)
        assert(len(str) > 0)
        print("Generating new stealth address...")
        stealth_addr = stealth_generate(inp)

MyPrompt().cmdloop()
