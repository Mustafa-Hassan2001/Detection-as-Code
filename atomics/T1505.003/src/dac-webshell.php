<?php
// Detection-as-Code LAB web shell simulator (T1505.003).
// SAFE BY DESIGN: runs only the three fixed recon commands below; user input selects a key
// in the allow-list and is never passed to the shell. Use only in the isolated lab and
// delete it after the test.
$allowed = ['id' => 'id', 'whoami' => 'whoami', 'uname' => 'uname -a'];
$c = isset($_GET['cmd']) ? $_GET['cmd'] : 'id';
if (!array_key_exists($c, $allowed)) {
    http_response_code(400);
    exit("not allowed\n");
}
header('Content-Type: text/plain');
echo shell_exec($allowed[$c]);
