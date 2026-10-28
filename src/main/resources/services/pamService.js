/**
 * Calls to the REST API of the PAM extension, at "api/session/ext/pam".
 */
angular.module('guacPam').factory('pamService', ['$injector', function pamService($injector) {

    // Required services
    var $q                    = $injector.get('$q');
    var authenticationService = $injector.get('authenticationService');

    var service = {};

    var send = function send(method, path, data, params) {

        // Once logged out, or once the session ended on the server, never
        // ask without a token: Guacamole 1.6 may then end the session of
        // another request, which it remembers wrongly
        if (!authenticationService.getCurrentToken())
            return $q.reject({ type : 'PERMISSION_DENIED', message : 'Not logged in.' });

        // The token in its header, as Guacamole sends it, never in the
        // address, which access logs and proxies record
        return authenticationService.request({
            method : method,
            url    : 'api/session/ext/pam/' + path,
            params : params,
            data   : data
        });

    };

    /**
     * How often the server's clock is compared with the browser's, in
     * milliseconds.
     */
    var CLOCK_CHECK_INTERVAL = 300000;

    /**
     * How far the server's clock (the database's, which the times of
     * checkouts and requests follow) is ahead of the browser's, in
     * milliseconds, as last measured; when, by the browser's clock, or null
     * until measured; and the measure under way, or null.
     */
    var clockOffset = 0;
    var clockChecked = null;
    var clockPending = null;

    /**
     * Measures the server's clock again if not measured lately. Resolves
     * once done, even if it fails (the last difference is then kept).
     */
    var syncClock = function syncClock() {
        if (clockPending)
            return clockPending;
        // Either way, as the browser's clock may have been set back
        if (clockChecked !== null && Math.abs(Date.now() - clockChecked) < CLOCK_CHECK_INTERVAL)
            return $q.resolve();
        var sent = Date.now();
        var pending = send('GET', 'time').then(function timeRetrieved(time) {
            var received = Date.now();
            clockOffset = time.now - Math.round((sent + received) / 2);
            clockChecked = received;
        }, angular.noop)['finally'](function clockSynced() {
            if (clockPending === pending)
                clockPending = null;
        });
        clockPending = pending;
        return pending;
    };

    /**
     * Calls the API once the server's clock is known, so what it returns
     * is compared with {@link service.now}.
     */
    var request = function request(method, path, data, params) {
        return syncClock().then(function clockKnown() {
            return send(method, path, data, params);
        });
    };

    /**
     * The server's time now, in milliseconds since the epoch: what the times
     * the API returns are compared with, rather than the browser's clock,
     * which may differ from the server's.
     */
    service.now = function now() {
        return Date.now() + clockOffset;
    };

    /**
     * Identifier of the data source whose connections are managed, as
     * { identifier }.
     */
    service.getDataSource = function getDataSource() {
        return request('GET', 'data-source');
    };

    /**
     * The request for the user's access under way, which those asking
     * meanwhile share, such as the sections of the Preferences page loading
     * together, and the token it was made with.
     */
    var accessPending = null;
    var accessToken = null;

    /**
     * What the user may do with PAM, each caller receiving their own copy.
     */
    service.getAccess = function getAccess() {
        var token = authenticationService.getCurrentToken();
        if (!accessPending || accessToken !== token) {
            var pending = request('GET', 'access')['finally'](function accessDone() {
                if (accessPending === pending)
                    accessPending = null;
            });
            accessPending = pending;
            accessToken = token;
        }
        return accessPending.then(angular.copy);
    };

    /**
     * Password policies: names for anyone, with their rules and what uses
     * each for administrators.
     */
    service.getPasswordPolicies = function getPasswordPolicies() {
        return request('GET', 'password-policies');
    };

    /**
     * The rules of passwords without a password policy.
     */
    service.getDefaultPasswordRules = function getDefaultPasswordRules() {
        return request('GET', 'password-policies/default');
    };

    service.createPasswordPolicy = function createPasswordPolicy(policy) {
        return request('POST', 'password-policies', policy);
    };

    service.updatePasswordPolicy = function updatePasswordPolicy(policy) {
        return request('PUT', 'password-policies/' + encodeURIComponent(policy.id), policy);
    };

    service.deletePasswordPolicy = function deletePasswordPolicy(id) {
        return request('DELETE', 'password-policies/' + encodeURIComponent(id));
    };

    /**
     * Example passwords of the given rules, saved or not, with their
     * strength, as { examples, bits }.
     */
    service.getExamplePasswords = function getExamplePasswords(rules) {
        return request('POST', 'password-policies/examples', rules);
    };

    /**
     * The settings shared by every server (administrators only).
     */
    service.getSettings = function getSettings() {
        return request('GET', 'settings');
    };

    /**
     * Whether this server runs the HA module ("ha"), and why it is on
     * standby ("standby", such as "OTHER_SERVER"), or null if PAM works on
     * it.
     */
    service.getServer = function getServer() {
        return request('GET', 'settings/server');
    };

    /**
     * Changes shared settings, all or none: each by name, to a value, or to
     * null for its default. Resolves with the settings as then.
     */
    service.updateSettings = function updateSettings(values) {
        return request('PUT', 'settings', values);
    };

    /**
     * Every language of emails, English first, with how many users chose
     * each (administrators only).
     */
    service.getEmailLanguages = function getEmailLanguages() {
        return request('GET', 'email-languages');
    };

    /**
     * English as built into the extension, to translate from.
     */
    service.getBuiltInEmailLanguage = function getBuiltInEmailLanguage() {
        return request('GET', 'email-languages/built-in');
    };

    /**
     * A language of emails as in effect, complete, as its file exports it.
     */
    service.getEmailLanguage = function getEmailLanguage(code) {
        return request('GET', 'email-languages/' + encodeURIComponent(code));
    };

    /**
     * Adds or replaces the language of its code.
     */
    service.saveEmailLanguage = function saveEmailLanguage(language) {
        return request('PUT', 'email-languages/' + encodeURIComponent(language.code), language);
    };

    /**
     * Deletes an added language; for English, restores what is built in.
     */
    service.deleteEmailLanguage = function deleteEmailLanguage(code) {
        return request('DELETE', 'email-languages/' + encodeURIComponent(code));
    };

    /**
     * The subject and text of a kind of email in a language as given,
     * unsaved, for a sample event. Resolves with "subject" and "body".
     */
    service.previewEmailLanguage = function previewEmailLanguage(language, kind) {
        return request('POST', 'email-languages/preview', { language : language, kind : kind });
    };

    /**
     * Sends a test through an output of events ("syslog", "email"), as
     * saved. Resolves with whether it was sent ("sent"), and what was sent
     * where, or why not ("message").
     */
    service.testSettings = function testSettings(output) {
        return request('POST', 'settings/test/' + encodeURIComponent(output));
    };

    /**
     * Number of managed connections whose last rotation failed or could not
     * be confirmed (administrators only).
     */
    service.countRotationFailures = function countRotationFailures() {
        return request('GET', 'connections/failures/count');
    };

    /**
     * Turns a notification badge of the current user ("approvals" or
     * "rotations") on or off.
     */
    service.setBadgeShown = function setBadgeShown(badge, shown) {
        return request('PUT', 'preferences/badges/' + encodeURIComponent(badge), { shown : shown });
    };

    /**
     * Turns one kind of email of the current user ("everything",
     * "approvals" or "own") on or off.
     */
    service.setEmailWanted = function setEmailWanted(kind, wanted) {
        return request('PUT', 'preferences/emails/' + encodeURIComponent(kind), { wanted : wanted });
    };

    /**
     * Sets the language of the current user's emails, such as "ar", or the
     * default one for null.
     */
    service.setEmailLanguage = function setEmailLanguage(language) {
        return request('PUT', 'preferences/email-language', { language : language });
    };

    /**
     * Management types with the forms of their platform settings.
     */
    service.getPlatformTypes = function getPlatformTypes() {
        return request('GET', 'platform-types');
    };

    service.getPlatforms = function getPlatforms() {
        return request('GET', 'platforms');
    };

    service.getPlatform = function getPlatform(id) {
        return request('GET', 'platforms/' + encodeURIComponent(id));
    };

    service.savePlatform = function savePlatform(platform) {
        var body = {
            name        : platform.name,
            description : platform.description,
            type        : platform.type,
            settings    : platform.settings,
            policy      : platform.policy
        };
        if (platform.id)
            return request('PUT', 'platforms/' + encodeURIComponent(platform.id), body);
        return request('POST', 'platforms', body);
    };

    /**
     * Tests a platform as edited, saved or not, resolving with its steps.
     * Secrets left empty are those of the saved platform, as when saving.
     */
    service.testPlatform = function testPlatform(platform) {
        return request('POST', 'platforms/test', {
            id       : platform.id,
            name     : platform.name,
            type     : platform.type,
            settings : platform.settings,
            policy   : platform.policy
        });
    };

    /**
     * Imports platforms, all or none, resolving with the report of each:
     * those named as existing ones update them if "update" is true, and
     * otherwise refuse the import.
     */
    service.importPlatforms = function importPlatforms(platforms, update) {
        return request('POST', 'platforms/import', { platforms : platforms, update : !!update });
    };

    /**
     * Adds back the default platforms missing by name, resolving with the
     * report of each: created, or skipped as it exists.
     */
    service.restoreDefaultPlatforms = function restoreDefaultPlatforms() {
        return request('POST', 'platforms/defaults');
    };

    service.deletePlatform = function deletePlatform(id) {
        return request('DELETE', 'platforms/' + encodeURIComponent(id));
    };

    service.validate = function validate(script) {
        return request('POST', 'validate', { script : script });
    };

    service.getConnections = function getConnections() {
        return request('GET', 'connections');
    };

    service.rotate = function rotate(identifier) {
        return request('POST', 'connections/' + encodeURIComponent(identifier) + '/rotate');
    };

    service.getRequests = function getRequests() {
        return request('GET', 'requests');
    };

    service.getRequest = function getRequest(identifier) {
        return request('GET', 'requests/' + encodeURIComponent(identifier));
    };

    /**
     * Checks out the password of an account, or shows it again to its
     * holder. The reason is only needed for a new checkout; the start
     * (milliseconds since 1970 UTC) only for access needing approval
     * requested ahead of time; and how many times the time limit is asked
     * for, if more than once. Resolves with the password, or, for accounts
     * needing approval, with the request status (which has no "password").
     */
    service.requestPassword = function requestPassword(identifier, reason, starts, periods) {
        var body = { reason : reason };
        if (starts)
            body.starts = String(starts);
        if (periods > 1)
            body.periods = String(periods);
        return request('POST', 'requests/' + encodeURIComponent(identifier), body);
    };

    /**
     * Shows the password of a connection the user holds, where the
     * connection allows it. Each call is recorded.
     */
    service.revealPassword = function revealPassword(identifier) {
        return request('POST', 'requests/' + encodeURIComponent(identifier) + '/password');
    };

    /**
     * Cancels the user's own request awaiting approval.
     */
    service.cancelRequest = function cancelRequest(identifier) {
        return request('DELETE', 'requests/' + encodeURIComponent(identifier) + '/pending');
    };

    /**
     * Extends the user's checkout, or asks for it to be extended where
     * approval is needed. Resolves with the request as the user now sees it.
     */
    service.extend = function extend(identifier, reason) {
        return request('POST', 'requests/' + encodeURIComponent(identifier) + '/extension', { reason : reason });
    };

    /**
     * Cancels the user's request to extend their checkout.
     */
    service.cancelExtension = function cancelExtension(identifier) {
        return request('DELETE', 'requests/' + encodeURIComponent(identifier) + '/extension');
    };

    /**
     * Cancels the user's own next approved access requested ahead of time,
     * not used yet.
     */
    service.cancelReservation = function cancelReservation(identifier) {
        return request('DELETE', 'requests/' + encodeURIComponent(identifier) + '/reservation');
    };

    /**
     * Every Account connection, with how many approvals it requires.
     */
    service.getAccounts = function getAccounts() {
        return request('GET', 'accounts');
    };

    service.getPendingApprovals = function getPendingApprovals() {
        return request('GET', 'approvals/pending');
    };

    /**
     * Number of requests awaiting approval that the user may decide on.
     */
    service.countApprovals = function countApprovals() {
        return request('GET', 'approvals/count');
    };

    service.searchApprovals = function searchApprovals(terms) {
        return request('GET', 'approvals/history', undefined, { contains : terms });
    };

    service.approve = function approve(id) {
        return request('POST', 'approvals/' + encodeURIComponent(id) + '/approve');
    };

    service.deny = function deny(id, reason) {
        return request('POST', 'approvals/' + encodeURIComponent(id) + '/deny', { reason : reason });
    };

    service.releasePassword = function releasePassword(identifier) {
        return request('POST', 'requests/' + encodeURIComponent(identifier) + '/release');
    };

    service.getActiveCheckouts = function getActiveCheckouts() {
        return request('GET', 'checkouts/active');
    };

    /**
     * Searches the checkout history, newest first. Every term must match the
     * user, connection, reason, or how and by whom the checkout ended.
     */
    service.searchCheckouts = function searchCheckouts(terms) {
        return request('GET', 'checkouts/history', undefined, { contains : terms });
    };

    service.revokeCheckout = function revokeCheckout(id) {
        return request('POST', 'checkouts/' + encodeURIComponent(id) + '/revoke');
    };

    return service;

}]);
