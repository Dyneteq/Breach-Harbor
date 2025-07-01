# import os
# os.system('calc.exe')

print("""
This package was created to prevent package name-based dependency confusion in pipreqs.
If you are reading this, and used pipreqs to generate requirements.txt file -- you are a 
victim of a dependency confusion attack. Go check your requirements.txt to ensure that only
required packages are listed inside.
""")

from . import views