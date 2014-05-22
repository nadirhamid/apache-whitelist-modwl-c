Apache White List Module
===================================================

A module to reverse DNS then forward DNS. Goal is to
prevent spoofing of an incoming user agent. 

More information here:
https://support.google.com/webmasters/answer/80553?hl=en

Examples
------------------------------------

	compiling:

	apxs -x -c a mod_wl.c

	Starting off

-------------------------

After you've compiled the module, open up httpd.conf
and type in:

	WLEnabled On
	WLDebug On
	WLBot "Googlebot/2.1 | bingbot/2.1"

And then point your browser to
{your_machines_ip}/any_static_file.html

and see the output it should look something like:

	WLEnabled: 1
	WLDebug: 1
	Initialized bot: Googlebot/2.1
	User Agent: {user_agent_string}
	Request landed in whitelist

Setting up a whitelist and blacklist
------------------------

To keep a reference of "good" useragents
and bad ones there are whitelists 

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

Sometimes we may want to do something with spoofed user agents. 
Here's an example of handling a bad user agent

	<Directory "/">
		WLEnabled On
		WLDebug On
		WLBot ""
		WLBlockedHandler "./blocked/why.html"
	</Directory>

We can do the same thing for whitelists as follows:
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

For more examples, check ./tests/

Matching browsers
------------------

	<Directory "/">
		WLEnable On
		WLBot "Mozilla5.0 | WebKit1.0 | Safari"
	</Directory>

More coming soon..
