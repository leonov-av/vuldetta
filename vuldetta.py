import vuldetta_code.functions_oval

f = open("com.ubuntu.mantic.usn.oval.xml", "r")
xml_content = f.read().encode('utf-8')
f.close()

print(vuldetta_code.functions_oval.get_processed_ubuntu_oval(xml_content))