"""Matrix rain effect for background"""

import tkinter as tk
import random
import string

class MatrixRain:
    def __init__(self, canvas, width, height):
        self.canvas = canvas
        self.width = width
        self.height = height
        self.font_size = 12
        self.columns = width // self.font_size
        self.drops = []
        
        # Initialize drop positions
        for i in range(self.columns):
            self.drops.append(random.randint(-height//self.font_size, 0))
        
        # Characters to display (including Japanese katakana)
        self.chars = string.ascii_letters + string.digits + \
                    "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ" + \
                    "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
    def update(self):
        """Update the matrix rain animation"""
        self.canvas.delete("matrix")
        
        for i in range(self.columns):
            # Get random character
            char = random.choice(self.chars)
            
            # Calculate position
            x = i * self.font_size
            y = self.drops[i] * self.font_size
            
            # Draw character with gradient effect
            if 0 < y < self.height:
                # Bright green for newest character
                self.canvas.create_text(x, y, text=char, fill="#00ff00", 
                                       font=("Courier", self.font_size, "bold"), 
                                       tags="matrix", anchor="nw")
                
                # Create trailing effect
                for j in range(1, 15):
                    trail_y = y - j * self.font_size
                    if trail_y > 0:
                        # Calculate fade color
                        fade = max(0, 255 - j * 20)
                        
                        if fade > 100:
                            color = f"#{fade:02x}ff{fade:02x}"
                        elif fade > 50:
                            color = f"#00{fade:02x}00"
                        else:
                            color = "#002200"
                        
                        trail_char = random.choice(self.chars)
                        self.canvas.create_text(x, trail_y, text=trail_char, 
                                               fill=color, 
                                               font=("Courier", self.font_size), 
                                               tags="matrix", anchor="nw")
            
            # Move drop down
            self.drops[i] += 1
            
            # Reset drop when it goes off screen
            if self.drops[i] * self.font_size > self.height + 300:
                self.drops[i] = random.randint(-20, -1)
                
            # Occasionally reset drops for variation
            if random.random() < 0.001:
                self.drops[i] = random.randint(-20, -1)
