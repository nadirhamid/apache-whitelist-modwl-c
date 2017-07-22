<?php
/**
 * An example for PHP use with mod_wl
 * this will output all the module's details 
 */

echo "Original Address is: " . $_SERVER{'MODWL_ORIGINAL'} . "<br />";
echo "Reverse DNS is: " . $_SERVER{'MODWL_REVERSE_DNS'} . "<br/>";
echo "Forward DNS is: " . $_SERVER{'MODWL_FORWARD_DNS'} . "<br/>";
echo "Status: " . $_SERVER{'MODWL_STATUS'};
?>
