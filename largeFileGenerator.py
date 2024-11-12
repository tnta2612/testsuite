# Python code to generate a large HTML file
html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Large HTML File</title>
</head>
<body>
"""

# Generate a large number of repetitive content
for i in range(1, 999999):
    print(i)
    html_content += f"<p>This is paragraph {i}</p>\n"

# Close the HTML structure
html_content += """
</body>
</html>
"""

# Write the content to a file
with open("largeFile.html", "w") as file:
    print("writing....")
    file.write(html_content)
    print("finished!")

print("Large HTML file generated.")