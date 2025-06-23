#!/bin/bash
echo "hello, $USER. I wish to list some files of your!"
echo "listing files in the current directory, $PWD"
ls

# Example 2

#!/bin/bash
echo -n '$USER=' # -n option stops echo from breaking the line
echo "$USER"
echo "\$USER=$USER"  # this does the same thing as the first two lines
#The output looks like this (assuming your username is elflord)
$USER=elflord

# Example 3
echo "Example 3"
#!/bin/bash
X=""
if [ -n "$X" ]; then 	# -n tests to see if the argument is non empty
		echo "the variable X is not the empty string"
	fi

# Example 4
echo "Example 4"

LS="ls"
LS_FLAGS="-al"


#Example 5




