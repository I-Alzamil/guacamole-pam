/**
 * Calls to the REST API of the PAM extension, at "api/session/ext/pam".
 */
angular.module('guacPam').factory('pamService', ['$injector', function pamService($injector) {

    // Required services
    var $q                    = $injector.get('$q');
    var authenticationService = $injector.get('authenticationService');
    var requestService        = $injector.get('requestService');

    var service = {};

    var request = function request(method, path, data, params) {

        // Once logged out, or once the session ended on the server, never
        // ask without a token: Guacamole 1.6 may then end the session of
        // another request, which it remembers wrongly
        if (!authenticationService.getCurrentToken())
            return $q.reject({ type : 'PERMISSION_DENIED', message : 'Not logged in.' });

        return requestService({
            method : method,
            url    : 'api/session/ext/pam/' + path,
            params : angular.extend({ token : authenticationService.getCurrentToken() }, params),
            data   : data
        });

    };

    /**
     * Identifier of the data source whose connections are managed, as
     * { identifier }.
     */
    service.getDataSource = function getDataSource() {
        return request('GET', 'data-source');
    };

    service.getAccess = function getAccess() {
        return request('GET', 'access');
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
