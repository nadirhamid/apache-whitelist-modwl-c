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

Starting off
-----------------------------------

After you've compiled the module, open up httpd.conf
and type in:

	LoadModule wl_module modules/mod_wl.so
	WLEnabled On
	WLDebug On
	WLBot "Googlebot/2.1 | bingbot/2.1"

And then point your browser to
{your_machines_ip}/any_static_file.html

the output should look something like:

	WLEnabled: 1
	WLDebug: 1
	Initialized bot: Googlebot/2.1
	User Agent: {user_agent_string}
	Request landed in whitelist

Setting up a whitelist and blacklist
------------------------

To keep a reference of "good" and "bad" useragents -- useful
for performace.

	<Directory "/">
		WLEnabled On
		WLDebug On
		WLBot "Googlebot/2.1 | Yahoo! Slurp | bingbot/2.1 | Yandexbot/2.1"
		WLList "/mod_wl.wl"
		WLBlacklist "/mod_wl.bl"
	</Directory>

Now "/mod_wl.wl" will store are safe ip address and "mod_wl.bl" will
keep the bad ones. 


Handling bad agents
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

We can also do the same thing with whitelists as follows:
WLAcceptedHandler "./"

Any user agent
-----------------

	<Directory "/">
		WLEnabled On
		WLDebug On
		WLBot "any"
		WLBotList "/mod_wl.bots"
		WLAutoAdd On
	</Directory>

This will watch any user agent and on a successful
request, add to the bot list. 


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
		WLInterop On
		WLBotList "/mod_wl.bots"
	</Directory>

This tells the module we want to upstream all
requests to a higher level language.

Some PHP code to put it together

	echo "Original Address is: " . $_SERVER{'MODWL_ORIGINAL'} . '<br />';
	echo "Reverse DNS is: $_SERVER{'MODWL_REVERSE_DNS'} . '<br/>';
	echo "Forward DNS is: $_SERVER{'MODWL_FORWARD_DNS'} . '<br/>';
	echo "Status: $_SERVER{'MODWL_STATUS'};


More Examples
------------------
You can find more examples in ./tests. 


Contributing
-----------------
Have a suggestion or want to add code to the 
project? I'm always ears on pro buno, give me a shout
@ matrix.nad@gmail.com   

More coming soon..
