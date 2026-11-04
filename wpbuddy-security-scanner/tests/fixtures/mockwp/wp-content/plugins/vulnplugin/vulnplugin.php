<?php
/**
 * Plugin Name: Vuln Plugin
 */
// dangerous: dynamic include from request
include($_GET['page']);
// SQLi: request var straight into query
$results = $wpdb->get_results("SELECT * FROM wp_posts WHERE id = " . $_GET['id']);
$id = $wpdb->get_var($wpdb->prepare("SELECT id FROM wp_posts WHERE id = %d", $_GET['safe_id']));
echo $_POST['message'];
system('ls ' . $_GET['dir']);
