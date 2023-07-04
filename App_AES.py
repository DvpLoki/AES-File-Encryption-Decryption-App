import streamlit as st
import tempfile
from StdMAES import MAES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
st.set_page_config(page_title='AES Encryption/Decryption',page_icon=':closed_lock_with_key:')


def generate_strong_key(password, salt):
    key = PBKDF2(password, salt, dkLen=16)  # Stretch the key using PBKDF2
    return key

def encrypt_file(data,password):
    salt = get_random_bytes(16) 
    key = generate_strong_key(password, salt)
    aes = MAES(key)
    l=len(data)
    i=0
    bar=st.progress(0)
    processedbytes=0
    t=tempfile.TemporaryFile()
    t.write(salt)
    while True:
        chunk = data[i:i+16]
        if len(chunk) == 0:
            break
        elif len(chunk) % 16 != 0:
            chunk += b' ' * (16 - len(chunk) % 16)
        cip = aes.encrypt(chunk)
        t.write(bytes(cip))
        processedbytes+=16
        p=(processedbytes+1)/l
        if p>1.0:
            p=1.0
        bar.progress(p,text='Encrypting...')
        i+=16
    t.seek(0)
    d=t.read()
    t.close()
    bar.empty()

    return  d

def decrypt_file(data, password):
    bar=st.progress(0)
    l=len(data)
    i=16
    salt = data[:16]
    key = generate_strong_key(password, salt)
    aes = MAES(key)
    td=tempfile.TemporaryFile()
    procesedbytes=0
    while True:
        chunk =data[i:i+16]
        if len(chunk) == 0:
            break
        pla = aes.decrypt(chunk)
        td.write(pla)
        procesedbytes+=16
        p=( procesedbytes+1)/l
        if p>1.0:
            p=1.0
        bar.progress(p,text='Decrypting...')
        i+=16
    td.seek(0)
    d=td.read()   
    bar.empty()    
    return  d

def main():
    st.title("File Encryption and Decryption")
    st.caption("This is a AES-128 based Encryption/Decryption tool compatible with any type of file")

    file = st.file_uploader("Upload a file")
    st.caption('This tool can process single file at a time')

    if file is not None:
        st.success("File uploaded successfully!")

        # Display file details
        file_details = {
            "Filename": file.name,
            "Type": file.type,
            "Size": len(file.read())
        }
        st.write("File Details:")
        st.write(file_details)

        password = st.text_input("Enter the 8-length key",type='password', max_chars=8)
        if len(password) == 8:
            l,r=st.columns(2)

            # Encryption
            if l.button("Encrypt"):
                encrypted_data = encrypt_file(file.getvalue(), password)
                
                encrypted_filename = f"encrypted_{file.name}"
                st.download_button(data=encrypted_data,file_name=encrypted_filename,label='Download')    
                st.balloons()


            # Decryption
            if r.button("Decrypt"):
                decrypted_data = decrypt_file(file.getvalue(), password)       
                decrypted_filename = f"decrypted_{file.name}"
                st.download_button(data=decrypted_data,file_name=decrypted_filename,label='Download')   
                st.balloons() 

        elif len(password) != 0:
            st.warning("Please enter an 8-character key")

   

    footer = """
    <style>
        .footer {
                position: fixed;
                
                left: 0;
                bottom: 0;
                width: 100%;
                background-color:black;
                padding: 10px;
                text-align: center;
                font-size: 14px;
                color:white;
            }
            a{
            text-decoration:none;
            }
            a:hover{ 
            color: white;
            text-decoration: none;
            }
    </style>

    <div class="footer">
        <h4>Made with &#10084; by Devarapu Lokesh</h4>
        <a href='https://www.linkedin.com/in/devarapu-lokesh-99057225a'><h6>LinkedIn</h6></a>
        <a href='https://github.com/DvpLoki'><h6>GitHub</h6></a>
    </div>
    """

    st.write(footer, unsafe_allow_html=True)

hide_st_style="""
            <style>
            #MainMenu {visibility:hidden;}
            footer {visibility:hidden;}
            header {visibility:hidden;}
            </style>
            """
st.markdown(hide_st_style,unsafe_allow_html=True)



if __name__ == "__main__":
    main()
