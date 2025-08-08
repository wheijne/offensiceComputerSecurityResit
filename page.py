import Tkinter as tk
import threading

class page(tk.Frame):
    """
    Represents a page on which an attack can be started.
    Need to override:
    - add_info_labels for the explaination of the attack.
    - add_entries for any extra inputs.
    - get_and_validate_inputs to retrieve the inputs and make sure they are correct. This function must return the arguments for the attacks start function.
    - start_text which gets displayed when the attack is started and takes the same order of arguments of the attacks start function.
    """
    
    def __init__(self, parent, title, attack_module):
        """
        Create an instance of the page.
        attack module is an instance of the attack class, must contain a start and stop function.
        """
        tk.Frame.__init__(self, parent)
        
        self.parent = parent
        self.attack_module = attack_module
        self.start_text = ""
        
        self.thread = None
        
        self.vcmd_ip = (self.register(validate_ip), '%P')
        self.vcmd_number = (self.register(validate_number), '%P')
        
        tk.Label(self, text=title, font=("Helvetica", 14, "bold")).pack()
        
        self.add_info_labels()
        self.add_entries()
        
        self.start_button = button(self, "Start", self.handle_start)
        self.stop_button = button(self, "Stop", self.handle_stop)
        self.stop_button.config(state="disabled")
        self.info_label = label(self, "")
    
    def add_info_labels(self):
        """
        Can be overriden to add info labels beneath the title.
        """
        pass
    
    def add_entries(self):
        """
        Can be overriden to add more inputs, other than interface and target IP.
        """
        self.interface = text_and_input(self, "Interface:")
        self.target_ip = text_and_input(self, "Target IP:")
        self.target_ip.config(validate="key", validatecommand=self.vcmd_ip)
    
    def handle_start(self):
        """
        Ran when the start button is clicked.
        """
        args = self.get_and_validate_inputs()
        if not args:
            self.info_label.config(text="Please check you inputs")
            return
        self.start_button.config(state="disabled")
        self.thread = threading.Thread(target=self.attack_module.start, args=args)
        self.thread.start()
        self.info_label.config(text=self.start_text % args)
        self.stop_button.config(state="normal")
        
    def get_and_validate_inputs(self):
        """
        Must be overriden to get and validate inputs.
        Must return the arguments of the start function.
        """
        pass
        
    def handle_stop(self):
        """
        Stops the attack.
        """
        self.stop_button.config(state="disabled")
        self.attack_module.stop()
        self.thread.join()
        self.info_label.config(text="Attack stopped")
        self.start_button.config(state="normal")
        

def label(parent, text):
    """
    Add a label.
    """
    lbl = tk.Label(parent, text=text)
    lbl.pack(fill="x")    
    return lbl
    
def text_and_input(parent, text):
    """
    Add an input with an info label.
    """
    container = tk.Frame(parent)
    tk.Label(container, text=text, width=20).pack(side="left")
    entry = tk.Entry(container, width=20)
    entry.pack(side="left")
    container.pack()
    return entry

def button(parent, text, handler):
    """
    Add a button.
    """
    btn = tk.Button(parent, text=text, command=handler)
    btn.pack()
    return btn
    
def validate_number(text):
    """
    Check whether the text is a positive number or an empty string
    """
    if text == "":
        return True
    decimal_count = text.count(".")
    if decimal_count > 1:
        return False
    if text.replace('.', '', 1).isdigit():
        return True
    return False
    
def validate_ip(text):
    """
    Check whether the text is (the start of) a valid IP address.
    """
    if text == "":
        return True
    splitted = text.split(".")
    if len(splitted) > 4:
        return False
    for i, t in enumerate(splitted):
        if t == '' and i == len(splitted) - 1:
            break
        if not t.isdigit():
            return False
        n = int(t)
        if n > 255 or n <= 0:
            return False
    return True
