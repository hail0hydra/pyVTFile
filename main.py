'''
Developed By    : Avinash Sharma
Date            : 29 January 2023           
Description     : This project extracts Data using an API provided by VirusTotal that anyone can access after creating an account.
Warnings        : Only works for files under 32 Mb
'''




from tkinter import Label
import customtkinter
from customtkinter import filedialog
import hashlib
from tkinter import messagebox
import requests
from PIL import Image, ImageTk

customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("dark-blue")

root = customtkinter.CTk()
root.geometry("600x500")
root.title("Virustotal: pyVTFile")
root.configure(fg_color="#272e3f")
root.resizable(width=False, height=False)



def check(hash):

    api_key = "cc967c699f9acfb6c7b76f89faca354399b9847ab75bcc9a19e17594ad9e9231"
    headers = {
            "accept" : "application/json",
            "X-Apikey": api_key
            }

    url = f"https://www.virustotal.com/api/v3/files/{hash}"
    response = requests.get(url, headers = headers)

    res = response.json()

    if 'data' in res:
        try:
            if (res["data"]["attributes"]["popular_threat_classification"]["popular_threat_name"][0]["count"]) > 0:
                messagebox.showwarning("Malicious", f"This file was voted malicious by {res['data']['attributes']['popular_threat_classification']['popular_threat_name'][0]['count']} companies")
        except:
            messagebox.showinfo("Harmless", "This file is marked as Harmless")
    elif 'error' in res:
        messagebox.showinfo("Harmless", "This file is marked as Harmless")



def on_drop(event=None):
    file_path = filedialog.askopenfilename()

    try:
        with open(file_path, "rb") as file:
            hash = hashlib.sha256(file.read()).hexdigest()
            check(hash)
    except:
        pass


frame = customtkinter.CTkFrame(master=root, fg_color="#313a4e")
frame.pack(pady = 20, padx = 60, fill="both", expand=True)

label = customtkinter.CTkLabel(master = frame, text="pyVTFile",font=("Comic Sans MS",32))
label.pack(pady=12, padx=10)


# Image
# image = Image.open("scan.png")
# my_img = image.resize((50, 50))
img = ImageTk.PhotoImage(Image.open("crate/scan.png"))
imgLabel = Label(master = frame, image=img, borderwidth=0) 
imgLabel.bind("<Button-1>", lambda event: on_drop())  # click on image and upload
imgLabel.pack()

# Drag and Drop more Like Upload
upload_button = customtkinter.CTkButton(master = frame, text = "Upload File",font=("Comic Sans MS", 24), command = on_drop)
upload_button.pack(pady=12, padx=10, expand=True)

# frame.bind("<Button-1>", on_drop) -- click anywhere and upload


root.mainloop()
