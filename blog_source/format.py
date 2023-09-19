import re
form = [] 
with open("./blog_source/cool_blogs.md",'r') as file : 
    for i in file.readlines()[2:] : 
        if line:=re.search("\|.*\|\[link\]\((.*)\)\|.*\|",i): 
            if sline := line.group(1).strip() : 
                form.append(sline)
with open("./blog_source/formmatted.md",'w') as file : 
    file.write("\n".join(form))