import sys


LOGO = """          _____                    _____                    _____                    _____                    _____                    _____          
         /\    \                  /\    \                  /\    \                  /\    \                  /\    \                  /\    \         
        /::\    \                /::\    \                /::\____\                /::\____\                /::\    \                /::\    \        
       /::::\    \              /::::\    \              /:::/    /               /:::/    /               /::::\    \              /::::\    \       
      /::::::\    \            /::::::\    \            /:::/   _/___            /:::/    /               /::::::\    \            /::::::\    \      
     /:::/\:::\    \          /:::/\:::\    \          /:::/   /\    \          /:::/    /               /:::/\:::\    \          /:::/\:::\    \     
    /:::/__\:::\    \        /:::/__\:::\    \        /:::/   /::\____\        /:::/    /               /:::/  \:::\    \        /:::/__\:::\    \    
   /::::\   \:::\    \      /::::\   \:::\    \      /:::/   /:::/    /       /:::/    /               /:::/    \:::\    \      /::::\   \:::\    \   
  /::::::\   \:::\    \    /::::::\   \:::\    \    /:::/   /:::/   _/___    /:::/    /      _____    /:::/    / \:::\    \    /::::::\   \:::\    \  
 /:::/\:::\   \:::\____\  /:::/\:::\   \:::\    \  /:::/___/:::/   /\    \  /:::/____/      /\    \  /:::/    /   \:::\ ___\  /:::/\:::\   \:::\____\ 
/:::/  \:::\   \:::|    |/:::/  \:::\   \:::\____\|:::|   /:::/   /::\____\|:::|    /      /::\____\/:::/____/     \:::|    |/:::/  \:::\   \:::|    |
\::/   |::::\  /:::|____|\::/    \:::\  /:::/    /|:::|__/:::/   /:::/    /|:::|____\     /:::/    /\:::\    \     /:::|____|\::/    \:::\  /:::|____|
 \/____|:::::\/:::/    /  \/____/ \:::\/:::/    /  \:::\/:::/   /:::/    /  \:::\    \   /:::/    /  \:::\    \   /:::/    /  \/_____/\:::\/:::/    / 
       |:::::::::/    /            \::::::/    /    \::::::/   /:::/    /    \:::\    \ /:::/    /    \:::\    \ /:::/    /            \::::::/    /  
       |::|\::::/    /              \::::/    /      \::::/___/:::/    /      \:::\    /:::/    /      \:::\    /:::/    /              \::::/    /   
       |::| \::/____/               /:::/    /        \:::\__/:::/    /        \:::\__/:::/    /        \:::\  /:::/    /                \::/____/    
       |::|  ~|                    /:::/    /          \::::::::/    /          \::::::::/    /          \:::\/:::/    /                  ~~          
       |::|   |                   /:::/    /            \::::::/    /            \::::::/    /            \::::::/    /                               
       \::|   |                  /:::/    /              \::::/    /              \::::/    /              \::::/    /                                
        \:|   |                  \::/    /                \::/____/                \::/____/                \::/____/                                 
         \|___|                   \/____/                  ~~                       ~~                       ~~                                       
                                                                                                                                                      """

class UI:
    logo = LOGO

    @staticmethod
    def print_progress_bar(iteration, total, prefix='', suffix='', length=50, fill='█'):
        percent = ("{0:.1f}").format(100 * (iteration / float(total))) # Calculate the percentage
        filled_length = int(length * iteration // total) # Calculate the filled length of the bar
        bar = fill * filled_length + '-' * (length - filled_length) # Generate the bar
        sys.stdout.write(f'\r{prefix} |{bar}| {percent}% {suffix}') # Print the bar
        sys.stdout.flush() # Flush the output
        # Print New Line on Complete
        if iteration == total: 
            print()