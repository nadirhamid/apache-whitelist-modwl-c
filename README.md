Apache White List Module
===================================================

This module will perform reverse and forward lookups on an incoming ip.
Afterwards it can perform the needed action based on your config. this is useful for preventing unwanted user agents from accessing a 
website. 

More information here:
https://support.google.com/webmasters/answer/80553?hl=en

An overview can also be found at:
https://modules.apache.org/modules.lua?id=13738


Compiling
------------------------------------

	compiling:

	apxs -i -a -c mod_wl.c

------------------------------------

Verifiying Incoming User-Agents
------------------------------------

	<Directory "/">
		WLEnabled On
		WLDebug On
	</Directory>


Handling "spoofs"
---------------------

Sometimes we may want to do something with unwanted user agents. 
Here's an example of handling one 

	<Directory "/">
		WLEnabled On
		WLDebug On
		WLBot ""
		WLBlockedHandler "./blocked/why.html"
	</Directory>

This will simply point any blocked user agent to "./blocked/why.html".

Any user agent
-----------------

	<Directory "/">
		WLEnabled On
		WLDebug On
		WLBot "any"
		WLAutoAdd On
	</Directory>

Matching browsers
------------------

	<Directory "/">
		WLEnable On
		WLBot "Mozilla5.0 | WebKit1.0 | Safari"
	</Directory>

No different from matching any search engine
bot.


Using mod_wl with PHP, Python, etc.
-----------------------------------

	<Directory "/">
		WLEnabled On
		WLDebug On
		WLForward On
	</Directory>

This tells the module we want to upstream all
requests to a higher level language.

Some PHP code to put it together
```
<?php
echo "Original Address is: " . $_SERVER{'MODWL_ORIGINAL'} . "<br />";
echo "Reverse DNS is: " . $_SERVER{'MODWL_REVERSE_DNS'} . "<br/>";
echo "Forward DNS is: " . $_SERVER{'MODWL_FORWARD_DNS'} . "<br/>";
echo "Status: " . $_SERVER{'MODWL_STATUS'};
?>
```


More Examples
------------------
You can find more examples in ./tests. 


Contributing
-----------------
Have a suggestion or want to add code to the 
project? I'm always ears on pro buno, give me a shout
@ matrix.nad@gmail.com   

More coming soon..
