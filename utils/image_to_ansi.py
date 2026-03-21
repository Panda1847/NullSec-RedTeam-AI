
import sys
import os
from PIL import Image
from ansiart import ansiart

def convert_image_to_ansi(image_path, output_width=80):
    try:
        img = Image.open(image_path)
        # Resize image to fit terminal width while maintaining aspect ratio
        width, height = img.size
        aspect_ratio = height / width
        new_height = int(output_width * aspect_ratio * 0.55) # Adjust for character aspect ratio
        img = img.resize((output_width, new_height))
        
        # Convert to ANSI art
        ansi_output = ansiart(img)
        return ansi_output
    except FileNotFoundError:
        return f"Error: Image file not found at {image_path}"
    except Exception as e:
        return f"Error converting image to ANSI: {e}"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 image_to_ansi.py <image_path> [output_width]")
        sys.exit(1)
    
    image_path = sys.argv[1]
    output_width = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    
    ansi_art = convert_image_to_ansi(image_path, output_width)
    print(ansi_art)
