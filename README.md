Apache White List Module
===================================================

This module blocks "unauthentic" HTTP requests by doing
a Forward/Reverse DNS lookup.

More information here:

https://support.google.com/webmasters/answer/80553?hl=en

https://modules.apache.org/modules.lua?id=13738


Compiling
------------------------------------

	compiling:

	apxs -i -a -c mod_wl.c

------------------------------------

Verifiying Incoming User-Agents
------------------------------------

		WLEnabled On


Any user agent
-----------------

		WLEnabled On
		WLBot "any"

Matching browsers
------------------

		WLEnabled On
		WLBot "Mozilla5.0 | WebKit1.0 | Safari"

Using mod_wl with PHP, Python, etc.
-----------------------------------

		WLEnabled On
		WLSubprocessEnv On

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
You can find more examples in ./examples. 
