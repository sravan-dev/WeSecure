<?php
/**
 * Plugin Name: WeSecure
 * Plugin URI: https://github.com/sravan-dev/WeSecure
 * Update URI: https://github.com/sravan-dev/WeSecure
 * Description: Protects WordPress against XSS attacks, file injection, and malicious modification of core files like index.php.
 * Version: 1.0.1
 * Author: Sravan M
 * Author URI: https://wesecure.dev
 * License: GPL-2.0+
 * Text Domain: wesecure
 */

if (!defined('ABSPATH')) {
    exit;
}

define('WESECURE_VERSION', '1.0.1');
define('WESECURE_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('WESECURE_PLUGIN_URL', plugin_dir_url(__FILE__));
define('WESECURE_GITHUB_REPO', 'sravan-dev/WeSecure');
define('WESECURE_PLUGIN_SLUG', 'wesecure/wesecure.php');

class WeSecure {

    private $log_file;
    private $protected_files = array(
        'index.php',
        'wp-config.php',
        'wp-settings.php',
        'wp-blog-header.php',
        'wp-load.php',
    );

    private $settings;

    private $default_settings = array(
        'enable_xss_protection'       => 1,
        'enable_file_injection'       => 1,
        'enable_file_integrity'       => 1,
        'enable_file_editor_block'    => 1,
        'enable_upload_php_block'     => 1,
        'enable_security_headers'     => 1,
        'enable_htaccess_protection'  => 1,
        'enable_rest_api_protection'  => 1,
        'enable_hide_wp_version'      => 1,
        'enable_login_protection'     => 1,
        'enable_xmlrpc_block'         => 1,
    );

    public function __construct() {
        $this->log_file = WP_CONTENT_DIR . '/wesecure-logs.log';
        $this->settings = get_option('wesecure_settings', $this->default_settings);

        // XSS Protection
        if ($this->is_enabled('enable_xss_protection')) {
            add_action('init', array($this, 'sanitize_request_inputs'), 1);
        }
        if ($this->is_enabled('enable_security_headers')) {
            add_action('send_headers', array($this, 'add_security_headers'));
        }

        // File Injection Protection
        if ($this->is_enabled('enable_file_injection')) {
            add_action('init', array($this, 'block_file_injection'), 1);
        }

        // Core File Integrity Monitor
        if ($this->is_enabled('enable_file_integrity')) {
            add_action('admin_init', array($this, 'check_core_file_integrity'));
            add_action('wesecure_integrity_check', array($this, 'scheduled_integrity_check'));
        }

        // Block direct file editing via admin
        if ($this->is_enabled('enable_file_editor_block')) {
            add_action('admin_init', array($this, 'disable_file_editor'));
        }

        // Block PHP execution in uploads
        if ($this->is_enabled('enable_upload_php_block')) {
            add_action('init', array($this, 'block_php_in_uploads'));
        }

        // .htaccess Protection
        if ($this->is_enabled('enable_htaccess_protection')) {
            add_action('admin_init', array($this, 'protect_htaccess'));
            add_action('wesecure_integrity_check', array($this, 'check_htaccess_integrity'));
        }

        // REST API User Enumeration Protection
        if ($this->is_enabled('enable_rest_api_protection')) {
            add_filter('rest_endpoints', array($this, 'block_rest_api_users'));
            add_filter('rest_authentication_errors', array($this, 'restrict_rest_api'));
        }

        // Hide WordPress Version & Server Info
        if ($this->is_enabled('enable_hide_wp_version')) {
            add_action('init', array($this, 'hide_wp_version'));
            add_action('send_headers', array($this, 'remove_server_headers'));
        }

        // Login Protection (brute force)
        if ($this->is_enabled('enable_login_protection')) {
            add_filter('authenticate', array($this, 'check_login_attempts'), 30, 3);
            add_action('wp_login_failed', array($this, 'log_failed_login'));
            add_action('wp_login', array($this, 'clear_login_attempts'), 10, 2);
        }

        // XML-RPC Block
        if ($this->is_enabled('enable_xmlrpc_block')) {
            add_filter('xmlrpc_enabled', '__return_false');
            add_filter('xmlrpc_methods', array($this, 'block_xmlrpc_methods'));
            add_action('init', array($this, 'block_xmlrpc_requests'), 1);
        }

        // Password Strength Enforcement
        add_action('user_profile_update_errors', array($this, 'enforce_strong_password'), 10, 3);
        add_action('validate_password_reset', array($this, 'enforce_strong_password_reset'), 10, 2);
        add_action('admin_notices', array($this, 'weak_password_warning'));

        // Admin dashboard
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_notices', array($this, 'display_admin_notices'));

        // Activation/Deactivation
        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));
    }

    /**
     * Check if a setting is enabled.
     */
    private function is_enabled($key) {
        return !empty($this->settings[$key]);
    }

    /**
     * Plugin activation - store file checksums and schedule integrity checks.
     */
    public function activate() {
        // Store default settings if not set
        if (!get_option('wesecure_settings')) {
            update_option('wesecure_settings', $this->default_settings);
        }

        $this->store_file_checksums();
        $this->backup_htaccess();

        if (!wp_next_scheduled('wesecure_integrity_check')) {
            wp_schedule_event(time(), 'hourly', 'wesecure_integrity_check');
        }

        // Create .htaccess in uploads to block PHP execution
        $this->create_uploads_htaccess();

        // Lock root .htaccess if protection enabled
        if ($this->is_enabled('enable_htaccess_protection')) {
            $this->lock_htaccess();
        }

        update_option('wesecure_activated', true);
    }

    /**
     * Plugin deactivation - clean up scheduled events.
     */
    public function deactivate() {
        wp_clear_scheduled_hook('wesecure_integrity_check');
    }

    // =========================================================================
    // XSS PROTECTION
    // =========================================================================

    /**
     * Sanitize all incoming request data for XSS patterns.
     */
    public function sanitize_request_inputs() {
        if (is_admin() && current_user_can('manage_options')) {
            return; // Allow admins in dashboard
        }

        $xss_patterns = array(
            '/<script\b[^>]*>(.*?)<\/script>/is',
            '/on\w+\s*=\s*["\'][^"\']*["\']/i',
            '/javascript\s*:/i',
            '/vbscript\s*:/i',
            '/expression\s*\(/i',
            '/data\s*:.*base64/i',
            '/<\s*iframe/i',
            '/<\s*object/i',
            '/<\s*embed/i',
            '/<\s*applet/i',
            '/<\s*form.*action\s*=/i',
            '/document\s*\.\s*(cookie|write|location)/i',
            '/window\s*\.\s*(location|open)/i',
            '/eval\s*\(/i',
            '/alert\s*\(/i',
            '/String\s*\.\s*fromCharCode/i',
        );

        $this->scan_array($_GET, 'GET', $xss_patterns);
        $this->scan_array($_POST, 'POST', $xss_patterns);
        $this->scan_array($_REQUEST, 'REQUEST', $xss_patterns);
        $this->scan_array($_COOKIE, 'COOKIE', $xss_patterns);
    }

    /**
     * Scan an array for XSS patterns.
     */
    private function scan_array($data, $source, $patterns) {
        if (!is_array($data)) {
            return;
        }

        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $this->scan_array($value, $source, $patterns);
                continue;
            }

            $decoded = $this->decode_value($value);

            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $decoded)) {
                    $this->log_threat('XSS', sprintf(
                        'Blocked XSS attempt in %s[%s]: %s',
                        $source,
                        sanitize_text_field($key),
                        substr(sanitize_text_field($value), 0, 200)
                    ));
                    $this->block_request('XSS attack detected and blocked by WeSecure.');
                }
            }
        }
    }

    /**
     * Decode value through multiple encoding layers.
     */
    private function decode_value($value) {
        $decoded = urldecode($value);
        $decoded = html_entity_decode($decoded, ENT_QUOTES, 'UTF-8');
        $decoded = preg_replace('/\x00/', '', $decoded); // Remove null bytes
        return $decoded;
    }

    /**
     * Add security headers to prevent XSS and clickjacking.
     */
    public function add_security_headers() {
        if (headers_sent()) {
            return;
        }

        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: SAMEORIGIN');
        header('X-XSS-Protection: 1; mode=block');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        header("Content-Security-Policy: script-src 'self' 'unsafe-inline' 'unsafe-eval' *.googleapis.com *.gstatic.com; object-src 'none';");
    }

    // =========================================================================
    // FILE INJECTION PROTECTION
    // =========================================================================

    /**
     * Block file injection attempts via request parameters.
     */
    public function block_file_injection() {
        $injection_patterns = array(
            '/\.\.\//i',                         // Directory traversal
            '/\/etc\/(passwd|shadow|hosts)/i',   // System file access
            '/proc\/self/i',                     // Process info
            '/php:\/\//i',                       // PHP stream wrappers
            '/data:\/\//i',                      // Data stream
            '/expect:\/\//i',                    // Expect wrapper
            '/zip:\/\//i',                       // Zip wrapper
            '/phar:\/\//i',                      // Phar wrapper
            '/file:\/\//i',                      // File wrapper
            '/glob:\/\//i',                      // Glob wrapper
            '/ssh2\./i',                         // SSH wrapper
            '/ogg:\/\//i',                       // OGG wrapper
            '/input:\/\//i',                     // Input wrapper
            '/filter\/.*convert/i',              // PHP filter chains
            '/\.php\x00/i',                      // Null byte injection
            '/\x00/i',                           // Null bytes
        );

        // Check query string
        $query_string = isset($_SERVER['QUERY_STRING']) ? $_SERVER['QUERY_STRING'] : '';
        $request_uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';

        foreach ($injection_patterns as $pattern) {
            if (preg_match($pattern, urldecode($query_string)) || preg_match($pattern, urldecode($request_uri))) {
                $this->log_threat('FILE_INJECTION', sprintf(
                    'Blocked file injection attempt: %s',
                    substr(sanitize_text_field($request_uri), 0, 200)
                ));
                $this->block_request('File injection attempt detected and blocked by WeSecure.');
            }
        }

        // Check all input arrays
        $this->scan_inputs_for_injection($_GET, 'GET', $injection_patterns);
        $this->scan_inputs_for_injection($_POST, 'POST', $injection_patterns);
        $this->scan_inputs_for_injection($_COOKIE, 'COOKIE', $injection_patterns);
    }

    /**
     * Scan input arrays for file injection patterns.
     */
    private function scan_inputs_for_injection($data, $source, $patterns) {
        if (!is_array($data)) {
            return;
        }

        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $this->scan_inputs_for_injection($value, $source, $patterns);
                continue;
            }

            $decoded = urldecode($value);

            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $decoded)) {
                    $this->log_threat('FILE_INJECTION', sprintf(
                        'Blocked file injection in %s[%s]: %s',
                        $source,
                        sanitize_text_field($key),
                        substr(sanitize_text_field($value), 0, 200)
                    ));
                    $this->block_request('File injection attempt detected and blocked by WeSecure.');
                }
            }
        }
    }

    /**
     * Block PHP execution in the uploads directory.
     */
    public function block_php_in_uploads() {
        $upload_dir = wp_upload_dir();
        $upload_path = $upload_dir['basedir'];

        if (isset($_SERVER['REQUEST_URI'])) {
            $request = urldecode($_SERVER['REQUEST_URI']);
            if (preg_match('/\/uploads\/.*\.ph(p|tml|ps)/i', $request)) {
                $this->log_threat('FILE_INJECTION', 'Blocked PHP execution attempt in uploads: ' . substr($request, 0, 200));
                $this->block_request('Unauthorized file execution blocked by WeSecure.');
            }
        }
    }

    /**
     * Create .htaccess in uploads directory to prevent PHP execution.
     */
    private function create_uploads_htaccess() {
        $upload_dir = wp_upload_dir();
        $htaccess_file = $upload_dir['basedir'] . '/.htaccess';

        $rules = "# WeSecure - Block PHP execution in uploads\n";
        $rules .= "<Files *.php>\n";
        $rules .= "deny from all\n";
        $rules .= "</Files>\n";
        $rules .= "<Files *.phtml>\n";
        $rules .= "deny from all\n";
        $rules .= "</Files>\n";
        $rules .= "<Files *.phps>\n";
        $rules .= "deny from all\n";
        $rules .= "</Files>\n";

        if (!file_exists($htaccess_file) || strpos(file_get_contents($htaccess_file), 'WeSecure') === false) {
            file_put_contents($htaccess_file, $rules, FILE_APPEND | LOCK_EX);
        }
    }

    // =========================================================================
    // CORE FILE INTEGRITY PROTECTION (index.php etc.)
    // =========================================================================

    /**
     * Store checksums of protected files on activation.
     */
    private function store_file_checksums() {
        $checksums = array();

        foreach ($this->protected_files as $file) {
            $filepath = ABSPATH . $file;
            if (file_exists($filepath)) {
                $checksums[$file] = hash_file('sha256', $filepath);
            }
        }

        update_option('wesecure_file_checksums', $checksums);
    }

    /**
     * Check core file integrity against stored checksums.
     */
    public function check_core_file_integrity() {
        $stored_checksums = get_option('wesecure_file_checksums', array());

        if (empty($stored_checksums)) {
            $this->store_file_checksums();
            return;
        }

        $alerts = array();

        foreach ($this->protected_files as $file) {
            $filepath = ABSPATH . $file;

            if (!file_exists($filepath)) {
                $alerts[] = sprintf('CRITICAL: Protected file missing: %s', $file);
                $this->log_threat('FILE_TAMPER', 'Protected file missing: ' . $file);
                continue;
            }

            $current_hash = hash_file('sha256', $filepath);

            if (isset($stored_checksums[$file]) && $stored_checksums[$file] !== $current_hash) {
                $alerts[] = sprintf('CRITICAL: Protected file modified: %s', $file);
                $this->log_threat('FILE_TAMPER', sprintf(
                    'File tampered: %s (expected: %s, got: %s)',
                    $file,
                    substr($stored_checksums[$file], 0, 16),
                    substr($current_hash, 0, 16)
                ));
            }
        }

        if (!empty($alerts)) {
            update_option('wesecure_alerts', $alerts);
            $this->notify_admin($alerts);
        }
    }

    /**
     * Scheduled integrity check (runs hourly).
     */
    public function scheduled_integrity_check() {
        $this->check_core_file_integrity();
    }

    /**
     * Disable the built-in WordPress file editor.
     */
    public function disable_file_editor() {
        if (!defined('DISALLOW_FILE_EDIT')) {
            define('DISALLOW_FILE_EDIT', true);
        }

        // Remove edit capabilities
        $role = get_role('administrator');
        if ($role && $role->has_cap('edit_files')) {
            // Just block the editor pages
            global $pagenow;
            if (in_array($pagenow, array('theme-editor.php', 'plugin-editor.php'))) {
                $this->log_threat('FILE_EDIT', 'Blocked access to file editor: ' . $pagenow);
                wp_die(
                    'File editing is disabled by WeSecure for security purposes.',
                    'Access Denied',
                    array('response' => 403)
                );
            }
        }
    }

    // =========================================================================
    // .HTACCESS PROTECTION
    // =========================================================================

    /**
     * Protect .htaccess from unauthorized modifications.
     */
    public function protect_htaccess() {
        $htaccess_path = ABSPATH . '.htaccess';

        if (!file_exists($htaccess_path)) {
            return;
        }

        // Store checksum if not stored yet
        $stored = get_option('wesecure_htaccess_checksum', '');
        if (empty($stored)) {
            update_option('wesecure_htaccess_checksum', hash_file('sha256', $htaccess_path));
            return;
        }

        // Check for modifications
        $current_hash = hash_file('sha256', $htaccess_path);
        if ($stored !== $current_hash) {
            // Scan for malicious patterns in .htaccess
            $content = file_get_contents($htaccess_path);
            $malicious_patterns = array(
                '/RewriteRule.*eval\s*\(/i',
                '/RewriteRule.*base64_decode/i',
                '/php_value\s+auto_prepend_file/i',
                '/php_value\s+auto_append_file/i',
                '/SetHandler\s+application\/x-httpd-php/i',
                '/AddHandler\s+.*\.php/i',
                '/AddType\s+application\/x-httpd-php/i',
                '/<FilesMatch.*\.(jpg|gif|png).*php/i',
                '/RewriteRule.*http(s)?:\/\/[^w]/i', // Redirect to external (not www)
            );

            $is_malicious = false;
            foreach ($malicious_patterns as $pattern) {
                if (preg_match($pattern, $content)) {
                    $is_malicious = true;
                    $this->log_threat('HTACCESS_HACK', 'Malicious pattern detected in .htaccess: ' . $pattern);
                    break;
                }
            }

            if ($is_malicious) {
                // Restore from backup if available
                $backup = get_option('wesecure_htaccess_backup', '');
                if (!empty($backup)) {
                    file_put_contents($htaccess_path, $backup);
                    $this->log_threat('HTACCESS_HACK', '.htaccess restored from clean backup after malicious modification detected.');
                }

                $alerts = get_option('wesecure_alerts', array());
                $alerts[] = 'CRITICAL: .htaccess was maliciously modified and restored by WeSecure.';
                update_option('wesecure_alerts', $alerts);
                $this->notify_admin($alerts);
            } else {
                // Legitimate change (maybe by plugin/WP update) — log but don't block
                $this->log_threat('HTACCESS_CHANGE', '.htaccess modified (possibly legitimate). Review recommended.');
                $alerts = get_option('wesecure_alerts', array());
                $alerts[] = 'WARNING: .htaccess was modified. Please verify the changes are legitimate.';
                update_option('wesecure_alerts', $alerts);
            }
        }
    }

    /**
     * Check .htaccess integrity on scheduled cron.
     */
    public function check_htaccess_integrity() {
        $this->protect_htaccess();
    }

    /**
     * Store clean .htaccess backup.
     */
    private function backup_htaccess() {
        $htaccess_path = ABSPATH . '.htaccess';
        if (file_exists($htaccess_path)) {
            $content = file_get_contents($htaccess_path);
            update_option('wesecure_htaccess_backup', $content);
            update_option('wesecure_htaccess_checksum', hash_file('sha256', $htaccess_path));
        }
    }

    /**
     * Lock .htaccess file permissions (make read-only).
     */
    private function lock_htaccess() {
        $htaccess_path = ABSPATH . '.htaccess';
        if (file_exists($htaccess_path) && strtoupper(substr(PHP_OS, 0, 3)) !== 'WIN') {
            @chmod($htaccess_path, 0444);
        }
    }

    /**
     * Unlock .htaccess file permissions (restore writable).
     */
    private function unlock_htaccess() {
        $htaccess_path = ABSPATH . '.htaccess';
        if (file_exists($htaccess_path) && strtoupper(substr(PHP_OS, 0, 3)) !== 'WIN') {
            @chmod($htaccess_path, 0644);
        }
    }

    // =========================================================================
    // REST API USER ENUMERATION PROTECTION
    // =========================================================================

    /**
     * Block REST API user endpoints for unauthenticated users.
     */
    public function block_rest_api_users($endpoints) {
        if (!is_user_logged_in()) {
            // Remove user endpoints
            if (isset($endpoints['/wp/v2/users'])) {
                unset($endpoints['/wp/v2/users']);
            }
            if (isset($endpoints['/wp/v2/users/(?P<id>[\d]+)'])) {
                unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
            }
        }
        return $endpoints;
    }

    /**
     * Restrict REST API access for unauthenticated users (optional strict mode).
     */
    public function restrict_rest_api($result) {
        if (true === $result || is_wp_error($result)) {
            return $result;
        }

        // Allow specific public endpoints (posts, pages, etc.)
        $allowed_routes = array('/wp/v2/posts', '/wp/v2/pages', '/wp/v2/categories', '/wp/v2/tags', '/oembed/');
        $current_route = isset($GLOBALS['wp']->query_vars['rest_route']) ? $GLOBALS['wp']->query_vars['rest_route'] : '';

        if (!is_user_logged_in() && !empty($current_route)) {
            // Block user-related API calls
            if (strpos($current_route, '/wp/v2/users') !== false) {
                $this->log_threat('REST_API', 'Blocked REST API user enumeration attempt: ' . $current_route);
                return new \WP_Error(
                    'rest_forbidden',
                    'Access denied by WeSecure.',
                    array('status' => 403)
                );
            }
        }

        return $result;
    }

    // =========================================================================
    // HIDE WORDPRESS VERSION & SERVER INFO
    // =========================================================================

    /**
     * Remove WordPress version from all output.
     */
    public function hide_wp_version() {
        // Remove version from head
        remove_action('wp_head', 'wp_generator');

        // Remove version from RSS feeds
        add_filter('the_generator', '__return_empty_string');

        // Remove version from scripts and styles
        add_filter('style_loader_src', array($this, 'remove_version_query'), 9999);
        add_filter('script_loader_src', array($this, 'remove_version_query'), 9999);
    }

    /**
     * Remove version query string from enqueued assets.
     */
    public function remove_version_query($src) {
        if (strpos($src, 'ver=')) {
            $src = remove_query_arg('ver', $src);
        }
        return $src;
    }

    /**
     * Remove server info headers (X-Powered-By, Server).
     */
    public function remove_server_headers() {
        if (headers_sent()) {
            return;
        }
        header_remove('X-Powered-By');
        header_remove('Server');
        header('X-Powered-By: WeSecure');
    }

    // =========================================================================
    // LOGIN BRUTE FORCE PROTECTION
    // =========================================================================

    /**
     * Check if IP is locked out from too many failed login attempts.
     */
    public function check_login_attempts($user, $username, $password) {
        if (empty($username) || empty($password)) {
            return $user;
        }

        $ip = $this->get_client_ip();
        $transient_key = 'wesecure_login_attempts_' . md5($ip);
        $attempts = get_transient($transient_key);

        $max_attempts = 5;
        $lockout_duration = 15 * MINUTE_IN_SECONDS; // 15 min lockout

        if ($attempts !== false && $attempts >= $max_attempts) {
            $this->log_threat('BRUTE_FORCE', sprintf(
                'Login locked out for IP %s (username tried: %s)',
                $ip,
                sanitize_text_field($username)
            ));

            return new \WP_Error(
                'wesecure_lockout',
                sprintf(
                    '<strong>WeSecure:</strong> Too many failed login attempts. Please try again in %d minutes.',
                    ceil($lockout_duration / 60)
                )
            );
        }

        return $user;
    }

    /**
     * Log failed login attempt and increment counter.
     */
    public function log_failed_login($username) {
        $ip = $this->get_client_ip();
        $transient_key = 'wesecure_login_attempts_' . md5($ip);
        $attempts = get_transient($transient_key);

        if ($attempts === false) {
            $attempts = 0;
        }

        $attempts++;
        $lockout_duration = 15 * MINUTE_IN_SECONDS;
        set_transient($transient_key, $attempts, $lockout_duration);

        $this->log_threat('LOGIN_FAIL', sprintf(
            'Failed login attempt #%d for username "%s" from IP %s',
            $attempts,
            sanitize_text_field($username),
            $ip
        ));

        // Notify admin after 3 failed attempts
        if ($attempts === 3) {
            $alerts = get_option('wesecure_alerts', array());
            $alerts[] = sprintf('WARNING: Multiple failed login attempts from IP %s (username: %s)', $ip, sanitize_text_field($username));
            update_option('wesecure_alerts', $alerts);
        }
    }

    /**
     * Clear login attempts on successful login.
     */
    public function clear_login_attempts($username, $user) {
        $ip = $this->get_client_ip();
        $transient_key = 'wesecure_login_attempts_' . md5($ip);
        delete_transient($transient_key);
    }

    // =========================================================================
    // XML-RPC BLOCK
    // =========================================================================

    /**
     * Remove all XML-RPC methods.
     */
    public function block_xmlrpc_methods($methods) {
        return array(); // Return empty - no methods available
    }

    /**
     * Block XML-RPC requests at init level.
     */
    public function block_xmlrpc_requests() {
        if (isset($_SERVER['REQUEST_URI']) && strpos($_SERVER['REQUEST_URI'], 'xmlrpc.php') !== false) {
            $this->log_threat('XMLRPC', sprintf(
                'Blocked XML-RPC request from IP %s',
                $this->get_client_ip()
            ));
            status_header(403);
            header('Content-Type: text/plain');
            echo 'XML-RPC is disabled by WeSecure.';
            exit;
        }
    }

    // =========================================================================
    // PASSWORD STRENGTH ENFORCEMENT
    // =========================================================================

    /**
     * Enforce strong passwords on profile update.
     */
    public function enforce_strong_password($errors, $update, $user) {
        if (isset($_POST['pass1']) && !empty($_POST['pass1'])) {
            $password = $_POST['pass1'];
            $strength_error = $this->check_password_strength($password);
            if ($strength_error) {
                $errors->add('weak_password', '<strong>WeSecure:</strong> ' . $strength_error);
            }
        }
        return $errors;
    }

    /**
     * Enforce strong passwords on password reset.
     */
    public function enforce_strong_password_reset($errors, $user) {
        if (isset($_POST['pass1']) && !empty($_POST['pass1'])) {
            $password = $_POST['pass1'];
            $strength_error = $this->check_password_strength($password);
            if ($strength_error) {
                $errors->add('weak_password', '<strong>WeSecure:</strong> ' . $strength_error);
            }
        }
    }

    /**
     * Check password strength. Returns error message or false if strong.
     */
    private function check_password_strength($password) {
        $min_length = 12;

        if (strlen($password) < $min_length) {
            return sprintf('Password must be at least %d characters long.', $min_length);
        }

        if (!preg_match('/[A-Z]/', $password)) {
            return 'Password must contain at least one uppercase letter.';
        }

        if (!preg_match('/[a-z]/', $password)) {
            return 'Password must contain at least one lowercase letter.';
        }

        if (!preg_match('/[0-9]/', $password)) {
            return 'Password must contain at least one number.';
        }

        if (!preg_match('/[^A-Za-z0-9]/', $password)) {
            return 'Password must contain at least one special character (!@#$%^&* etc).';
        }

        // Check against common weak passwords
        $common_passwords = array(
            'password123', 'admin123456', 'qwerty123456', 'letmein12345',
            '123456789012', 'password1234', 'admin1234567', 'welcome12345',
            'changeme1234', 'iloveyou1234', 'wordpress123', 'admin@12345',
        );

        if (in_array(strtolower($password), $common_passwords)) {
            return 'This password is too common. Please choose a unique password.';
        }

        // Check if password contains username
        $current_user = wp_get_current_user();
        if ($current_user && stripos($password, $current_user->user_login) !== false) {
            return 'Password must not contain your username.';
        }

        return false; // Password is strong
    }

    /**
     * Show admin warning if current user has weak password (checks last set date).
     */
    public function weak_password_warning() {
        if (!current_user_can('manage_options')) {
            return;
        }

        // Check if admin password was recently set (within plugin activation)
        $user = wp_get_current_user();
        $password_last_changed = get_user_meta($user->ID, 'wesecure_password_checked', true);

        if (empty($password_last_changed)) {
            echo '<div class="notice notice-warning"><p>';
            echo '<strong>WeSecure:</strong> Please ensure your admin password meets security requirements: ';
            echo 'minimum 12 characters, uppercase + lowercase + numbers + special characters. ';
            echo '<a href="' . admin_url('profile.php') . '">Update Password</a>';
            echo '</p></div>';

            // Only show once per week
            update_user_meta($user->ID, 'wesecure_password_checked', time());
        } elseif ((time() - (int)$password_last_changed) > WEEK_IN_SECONDS) {
            delete_user_meta($user->ID, 'wesecure_password_checked');
        }
    }

    // =========================================================================
    // ADMIN INTERFACE
    // =========================================================================

    /**
     * Add admin menu page.
     */
    public function add_admin_menu() {
        add_menu_page(
            'WeSecure',
            'WeSecure',
            'manage_options',
            'wesecure',
            array($this, 'admin_page'),
            'dashicons-shield',
            80
        );
    }

    /**
     * Render admin dashboard page.
     */
    public function admin_page() {
        if (!current_user_can('manage_options')) {
            return;
        }

        // Handle settings save
        if (isset($_POST['wesecure_save_settings']) && wp_verify_nonce($_POST['_wpnonce'], 'wesecure_save_settings')) {
            $new_settings = array(
                'enable_xss_protection'       => isset($_POST['enable_xss_protection']) ? 1 : 0,
                'enable_file_injection'       => isset($_POST['enable_file_injection']) ? 1 : 0,
                'enable_file_integrity'       => isset($_POST['enable_file_integrity']) ? 1 : 0,
                'enable_file_editor_block'    => isset($_POST['enable_file_editor_block']) ? 1 : 0,
                'enable_upload_php_block'     => isset($_POST['enable_upload_php_block']) ? 1 : 0,
                'enable_security_headers'     => isset($_POST['enable_security_headers']) ? 1 : 0,
                'enable_htaccess_protection'  => isset($_POST['enable_htaccess_protection']) ? 1 : 0,
                'enable_rest_api_protection'  => isset($_POST['enable_rest_api_protection']) ? 1 : 0,
                'enable_hide_wp_version'      => isset($_POST['enable_hide_wp_version']) ? 1 : 0,
                'enable_login_protection'     => isset($_POST['enable_login_protection']) ? 1 : 0,
                'enable_xmlrpc_block'         => isset($_POST['enable_xmlrpc_block']) ? 1 : 0,
            );
            update_option('wesecure_settings', $new_settings);
            $this->settings = $new_settings;

            // Handle .htaccess lock/unlock based on setting
            if ($new_settings['enable_htaccess_protection']) {
                $this->backup_htaccess();
                $this->lock_htaccess();
            } else {
                $this->unlock_htaccess();
            }

            echo '<div class="notice notice-success"><p>Settings saved successfully.</p></div>';
        }

        // Handle re-checksum action
        if (isset($_POST['wesecure_rechecksum']) && wp_verify_nonce($_POST['_wpnonce'], 'wesecure_rechecksum')) {
            $this->store_file_checksums();
            $this->backup_htaccess();
            echo '<div class="notice notice-success"><p>File checksums updated successfully.</p></div>';
        }

        // Handle clear logs action
        if (isset($_POST['wesecure_clear_logs']) && wp_verify_nonce($_POST['_wpnonce'], 'wesecure_clear_logs')) {
            if (file_exists($this->log_file)) {
                file_put_contents($this->log_file, '');
            }
            echo '<div class="notice notice-success"><p>Logs cleared.</p></div>';
        }

        // Handle dismiss alerts
        if (isset($_POST['wesecure_dismiss_alerts']) && wp_verify_nonce($_POST['_wpnonce'], 'wesecure_dismiss_alerts')) {
            delete_option('wesecure_alerts');
            echo '<div class="notice notice-success"><p>Alerts dismissed.</p></div>';
        }

        $stored_checksums = get_option('wesecure_file_checksums', array());
        $alerts = get_option('wesecure_alerts', array());
        $logs = $this->get_recent_logs(50);

        ?>
        <div class="wrap">
            <h1><span class="dashicons dashicons-shield" style="font-size:30px;margin-right:10px;"></span>WeSecure Dashboard</h1>

            <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px;">

                <!-- Settings Card -->
                <div class="card" style="padding: 20px;">
                    <h2>Protection Settings</h2>
                    <form method="post">
                        <?php wp_nonce_field('wesecure_save_settings'); ?>
                        <table class="widefat striped">
                            <tr>
                                <td><label><input type="checkbox" name="enable_xss_protection" value="1" <?php checked($this->is_enabled('enable_xss_protection')); ?>> XSS Protection</label></td>
                                <td><small>Block cross-site scripting attacks in inputs</small></td>
                            </tr>
                            <tr>
                                <td><label><input type="checkbox" name="enable_file_injection" value="1" <?php checked($this->is_enabled('enable_file_injection')); ?>> File Injection Protection</label></td>
                                <td><small>Block path traversal &amp; PHP wrapper attacks</small></td>
                            </tr>
                            <tr>
                                <td><label><input type="checkbox" name="enable_file_integrity" value="1" <?php checked($this->is_enabled('enable_file_integrity')); ?>> Core File Integrity Monitor</label></td>
                                <td><small>Detect changes to index.php, wp-config.php, etc.</small></td>
                            </tr>
                            <tr>
                                <td><label><input type="checkbox" name="enable_file_editor_block" value="1" <?php checked($this->is_enabled('enable_file_editor_block')); ?>> Disable File Editor</label></td>
                                <td><small>Block WP theme/plugin editor</small></td>
                            </tr>
                            <tr>
                                <td><label><input type="checkbox" name="enable_upload_php_block" value="1" <?php checked($this->is_enabled('enable_upload_php_block')); ?>> Block PHP in Uploads</label></td>
                                <td><small>Prevent PHP execution in /uploads/</small></td>
                            </tr>
                            <tr>
                                <td><label><input type="checkbox" name="enable_security_headers" value="1" <?php checked($this->is_enabled('enable_security_headers')); ?>> Security Headers</label></td>
                                <td><small>Add X-XSS-Protection, CSP, X-Frame-Options</small></td>
                            </tr>
                            <tr style="background:#fff3cd;">
                                <td><label><input type="checkbox" name="enable_htaccess_protection" value="1" <?php checked($this->is_enabled('enable_htaccess_protection')); ?>> <strong>.htaccess Protection</strong></label></td>
                                <td><small>Monitor &amp; lock .htaccess from malicious edits (redirects, backdoors, PHP injection)</small></td>
                            </tr>
                            <tr style="background:#fff3cd;">
                                <td><label><input type="checkbox" name="enable_rest_api_protection" value="1" <?php checked($this->is_enabled('enable_rest_api_protection')); ?>> <strong>REST API User Protection</strong></label></td>
                                <td><small>Block username enumeration via /wp-json/wp/v2/users</small></td>
                            </tr>
                            <tr style="background:#fff3cd;">
                                <td><label><input type="checkbox" name="enable_hide_wp_version" value="1" <?php checked($this->is_enabled('enable_hide_wp_version')); ?>> <strong>Hide WP Version &amp; Server Info</strong></label></td>
                                <td><small>Remove PHP version, WP version, server headers from responses</small></td>
                            </tr>
                            <tr style="background:#fff3cd;">
                                <td><label><input type="checkbox" name="enable_login_protection" value="1" <?php checked($this->is_enabled('enable_login_protection')); ?>> <strong>Login Brute Force Protection</strong></label></td>
                                <td><small>Lock out IP after 5 failed attempts (15 min cooldown)</small></td>
                            </tr>
                            <tr style="background:#fff3cd;">
                                <td><label><input type="checkbox" name="enable_xmlrpc_block" value="1" <?php checked($this->is_enabled('enable_xmlrpc_block')); ?>> <strong>Block XML-RPC</strong></label></td>
                                <td><small>Disable xmlrpc.php completely (prevents brute force amplification &amp; DDoS)</small></td>
                            </tr>
                        </table>
                        <p style="margin-top:15px;">
                            <input type="submit" name="wesecure_save_settings" class="button button-primary" value="Save Settings">
                        </p>
                    </form>
                </div>

                <!-- File Integrity Card -->
                <div class="card" style="padding: 20px;">
                    <h2>Protected Files</h2>
                    <table class="widefat striped">
                        <thead><tr><th>File</th><th>Status</th></tr></thead>
                        <tbody>
                        <?php
                        // Include .htaccess in protected files display
                        $display_files = $this->protected_files;
                        if ($this->is_enabled('enable_htaccess_protection')) {
                            $display_files[] = '.htaccess';
                        }
                        foreach ($display_files as $file): ?>
                            <?php
                            $filepath = ABSPATH . $file;
                            $status = 'OK';
                            $color = 'green';
                            if (!file_exists($filepath)) {
                                $status = 'MISSING';
                                $color = 'red';
                            } elseif ($file === '.htaccess') {
                                $ht_checksum = get_option('wesecure_htaccess_checksum', '');
                                if (!empty($ht_checksum) && $ht_checksum !== hash_file('sha256', $filepath)) {
                                    $status = 'MODIFIED';
                                    $color = 'orange';
                                }
                            } elseif (isset($stored_checksums[$file])) {
                                $current = hash_file('sha256', $filepath);
                                if ($current !== $stored_checksums[$file]) {
                                    $status = 'MODIFIED';
                                    $color = 'red';
                                }
                            }
                            ?>
                            <tr>
                                <td><code><?php echo esc_html($file); ?></code></td>
                                <td><span style="color:<?php echo $color; ?>; font-weight:bold;"><?php echo esc_html($status); ?></span></td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                    <form method="post" style="margin-top:10px;">
                        <?php wp_nonce_field('wesecure_rechecksum'); ?>
                        <input type="submit" name="wesecure_rechecksum" class="button button-secondary" value="Re-baseline Checksums">
                        <p class="description">Updates stored checksums to current file state (use after legitimate updates).</p>
                    </form>
                </div>
            </div>

            <!-- .htaccess Info -->
            <?php if ($this->is_enabled('enable_htaccess_protection')): ?>
            <div class="card" style="padding: 20px; margin-top: 20px; border-left: 4px solid #0073aa;">
                <h2>.htaccess Protection Active</h2>
                <p>WeSecure monitors your root <code>.htaccess</code> file for:</p>
                <ul style="list-style:disc; margin-left:20px;">
                    <li>Malicious redirects to external spam/phishing sites</li>
                    <li>PHP execution handlers injected to run backdoors</li>
                    <li><code>auto_prepend_file</code> / <code>auto_append_file</code> injection</li>
                    <li>File type handler manipulation (e.g., treating images as PHP)</li>
                    <li>Base64/eval obfuscation patterns</li>
                </ul>
                <p><strong>File permissions:</strong>
                <?php
                $htaccess_path = ABSPATH . '.htaccess';
                if (file_exists($htaccess_path)) {
                    $perms = substr(sprintf('%o', fileperms($htaccess_path)), -4);
                    echo '<code>' . $perms . '</code>';
                    if ($perms === '0444') {
                        echo ' <span style="color:green;">(locked - read only)</span>';
                    } else {
                        echo ' <span style="color:orange;">(writable - consider locking)</span>';
                    }
                } else {
                    echo '<span style="color:gray;">File not found</span>';
                }
                ?>
                </p>
            </div>
            <?php endif; ?>

            <!-- Alerts -->
            <?php if (!empty($alerts)): ?>
            <div class="card" style="padding: 20px; margin-top: 20px; border-left: 4px solid #dc3232;">
                <h2 style="color: #dc3232;">Security Alerts</h2>
                <ul>
                    <?php foreach ($alerts as $alert): ?>
                        <li style="color:#dc3232;">&#9888; <?php echo esc_html($alert); ?></li>
                    <?php endforeach; ?>
                </ul>
                <form method="post" style="margin-top:10px;">
                    <?php wp_nonce_field('wesecure_dismiss_alerts'); ?>
                    <input type="submit" name="wesecure_dismiss_alerts" class="button button-secondary" value="Dismiss Alerts">
                </form>
            </div>
            <?php endif; ?>

            <!-- Logs -->
            <div class="card" style="padding: 20px; margin-top: 20px;">
                <h2>Recent Threat Log</h2>
                <?php if (empty($logs)): ?>
                    <p style="color:green;">No threats detected. Your site is secure.</p>
                <?php else: ?>
                    <div style="max-height:400px; overflow-y:auto; background:#1d2327; padding:15px; border-radius:4px;">
                        <pre style="color:#00ff00; font-size:12px; margin:0; white-space:pre-wrap;"><?php echo esc_html($logs); ?></pre>
                    </div>
                    <form method="post" style="margin-top:10px;">
                        <?php wp_nonce_field('wesecure_clear_logs'); ?>
                        <input type="submit" name="wesecure_clear_logs" class="button button-secondary" value="Clear Logs">
                    </form>
                <?php endif; ?>
            </div>
        </div>
        <?php
    }

    /**
     * Display admin notices for security alerts.
     */
    public function display_admin_notices() {
        $alerts = get_option('wesecure_alerts', array());
        if (!empty($alerts)) {
            echo '<div class="notice notice-error"><p><strong>WeSecure Alert:</strong> ';
            echo esc_html(count($alerts)) . ' security issue(s) detected. ';
            echo '<a href="' . admin_url('admin.php?page=wesecure') . '">View Details</a></p></div>';
        }
    }

    // =========================================================================
    // UTILITY METHODS
    // =========================================================================

    /**
     * Block a malicious request.
     */
    private function block_request($message) {
        status_header(403);
        wp_die(
            esc_html($message),
            'Forbidden - WeSecure',
            array('response' => 403)
        );
    }

    /**
     * Log a security threat.
     */
    private function log_threat($type, $message) {
        $entry = sprintf(
            "[%s] [%s] [IP: %s] %s\n",
            current_time('Y-m-d H:i:s'),
            $type,
            $this->get_client_ip(),
            $message
        );

        file_put_contents($this->log_file, $entry, FILE_APPEND | LOCK_EX);
    }

    /**
     * Get recent log entries.
     */
    private function get_recent_logs($lines = 50) {
        if (!file_exists($this->log_file)) {
            return '';
        }

        $content = file_get_contents($this->log_file);
        $all_lines = explode("\n", trim($content));
        $recent = array_slice($all_lines, -$lines);
        return implode("\n", $recent);
    }

    /**
     * Get client IP address.
     */
    private function get_client_ip() {
        $headers = array(
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'REMOTE_ADDR',
        );

        foreach ($headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ip = $_SERVER[$header];
                if (strpos($ip, ',') !== false) {
                    $ip = trim(explode(',', $ip)[0]);
                }
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }

        return '0.0.0.0';
    }

    /**
     * Notify admin via email about security alerts.
     */
    private function notify_admin($alerts) {
        $admin_email = get_option('admin_email');
        $site_name = get_bloginfo('name');

        $subject = sprintf('[%s] WeSecure Security Alert', $site_name);
        $message = "WeSecure has detected the following security issues:\n\n";
        $message .= implode("\n", $alerts);
        $message .= "\n\nPlease review immediately at: " . admin_url('admin.php?page=wesecure');

        wp_mail($admin_email, $subject, $message);
    }
}

// =========================================================================
// GITHUB AUTO-UPDATER
// =========================================================================

class WeSecure_Updater {

    private $slug;
    private $plugin_file;
    private $github_repo;
    private $github_response;

    public function __construct() {
        $this->slug = 'wesecure';
        $this->plugin_file = WESECURE_PLUGIN_SLUG;
        $this->github_repo = WESECURE_GITHUB_REPO;

        add_filter('pre_set_site_transient_update_plugins', array($this, 'check_update'));
        add_filter('plugins_api', array($this, 'plugin_info'), 20, 3);
        add_filter('upgrader_post_install', array($this, 'after_install'), 10, 3);
    }

    /**
     * Fetch latest release info from GitHub.
     */
    private function get_github_release() {
        if (!empty($this->github_response)) {
            return $this->github_response;
        }

        $url = sprintf('https://api.github.com/repos/%s/releases/latest', $this->github_repo);

        $response = wp_remote_get($url, array(
            'headers' => array(
                'Accept' => 'application/vnd.github.v3+json',
            ),
            'timeout' => 10,
        ));

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return false;
        }

        $this->github_response = json_decode(wp_remote_retrieve_body($response));
        return $this->github_response;
    }

    /**
     * Check if an update is available.
     */
    public function check_update($transient) {
        if (empty($transient->checked)) {
            return $transient;
        }

        $release = $this->get_github_release();
        if (!$release) {
            return $transient;
        }

        // Get version from tag (strip 'v' prefix)
        $latest_version = ltrim($release->tag_name, 'v');
        $current_version = WESECURE_VERSION;

        if (version_compare($latest_version, $current_version, '>')) {
            $download_url = $this->get_download_url($release);

            $transient->response[$this->plugin_file] = (object) array(
                'slug'        => $this->slug,
                'plugin'      => $this->plugin_file,
                'new_version' => $latest_version,
                'url'         => sprintf('https://github.com/%s', $this->github_repo),
                'package'     => $download_url,
                'icons'       => array(
                    'default' => 'dashicons-shield',
                ),
            );
        }

        return $transient;
    }

    /**
     * Get download URL from release assets or zipball.
     */
    private function get_download_url($release) {
        // Check for uploaded zip asset first
        if (!empty($release->assets)) {
            foreach ($release->assets as $asset) {
                if (strpos($asset->name, '.zip') !== false) {
                    return $asset->browser_download_url;
                }
            }
        }

        // Fallback to zipball
        return $release->zipball_url;
    }

    /**
     * Provide plugin information for the update details popup.
     */
    public function plugin_info($result, $action, $args) {
        if ($action !== 'plugin_information') {
            return $result;
        }

        if (!isset($args->slug) || $args->slug !== $this->slug) {
            return $result;
        }

        $release = $this->get_github_release();
        if (!$release) {
            return $result;
        }

        $latest_version = ltrim($release->tag_name, 'v');

        $plugin_info = new \stdClass();
        $plugin_info->name = 'WeSecure';
        $plugin_info->slug = $this->slug;
        $plugin_info->version = $latest_version;
        $plugin_info->author = '<a href="https://github.com/sravan-dev">Sravan M</a>';
        $plugin_info->homepage = sprintf('https://github.com/%s', $this->github_repo);
        $plugin_info->requires = '5.0';
        $plugin_info->tested = '6.7';
        $plugin_info->requires_php = '7.4';
        $plugin_info->downloaded = 0;
        $plugin_info->last_updated = $release->published_at;
        $plugin_info->download_link = $this->get_download_url($release);

        // Convert markdown release notes to HTML
        $plugin_info->sections = array(
            'description' => 'WordPress Security Plugin - Protects against XSS, file injection, brute force, XML-RPC attacks, .htaccess tampering, and more.',
            'changelog'   => nl2br(esc_html($release->body)),
        );

        $plugin_info->banners = array();

        return $plugin_info;
    }

    /**
     * Rename folder after install (GitHub zips have weird folder names).
     */
    public function after_install($response, $hook_extra, $result) {
        if (!isset($hook_extra['plugin']) || $hook_extra['plugin'] !== $this->plugin_file) {
            return $result;
        }

        global $wp_filesystem;

        $install_dir = plugin_dir_path(dirname(__FILE__));
        $proper_dir = $install_dir . $this->slug;

        // Move to proper directory name
        $wp_filesystem->move($result['destination'], $proper_dir);
        $result['destination'] = $proper_dir;

        // Reactivate plugin
        activate_plugin($this->plugin_file);

        return $result;
    }
}

// Initialize plugin
new WeSecure();
new WeSecure_Updater();
