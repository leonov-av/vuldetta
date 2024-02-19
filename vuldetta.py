import vuldetta_code.functions_oval

# $ wget https://security-metadata.canonical.com/oval/com.ubuntu.$(lsb_release -cs).usn.oval.xml.bz2

f = open("com.ubuntu.mantic.usn.oval.xml", "r")
xml_content = f.read().encode('utf-8')
f.close()

vuldetta_code.functions_oval.get_processed_ubuntu_oval(xml_content)