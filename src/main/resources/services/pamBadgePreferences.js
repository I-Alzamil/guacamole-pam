/**
 * Which notification badges the current user may have and wants, as chosen
 * on the Preferences tab, starting or stopping the badges accordingly:
 * "approvals" for approvers, "rotations" for administrators.
 */
angular.module('guacPam').factory('pamBadgePreferences', ['$injector', function pamBadgePreferences($injector) {

    var pamApprovalBadge = $injector.get('pamApprovalBadge');
    var pamRotationBadge = $injector.get('pamRotationBadge');
    var pamService       = $injector.get('pamService');

    /**
     * Counter of each badge.
     */
    var BADGES = {
        approvals : pamApprovalBadge,
        rotations : pamRotationBadge
    };

    var service = {};

    /**
     * Whether the user may have each badge, and whether they want it.
     */
    service.state = {
        loaded    : false,
        available : { approvals : false, rotations : false },
        shown     : { approvals : true, rotations : true },
        saving    : {}
    };

    var apply = function apply(badge) {
        BADGES[badge].start(service.state.available[badge] && service.state.shown[badge]);
    };

    /**
     * Loads the user's access and choices, and starts the badges they want.
     */
    service.load = function load() {
        return pamService.getAccess().then(function accessRetrieved(access) {
            service.state.available = { approvals : access.approver, rotations : access.administrator };
            service.state.shown = angular.extend({ approvals : true, rotations : true }, access.badges);
            service.state.loaded = true;
            angular.forEach(BADGES, function startBadge(counter, badge) {
                apply(badge);
            });
        }, function accessFailed() {
            service.clear();
        });
    };

    /**
     * Saves the choice of showing a badge, put back if saving fails.
     */
    service.set = function set(badge, shown) {
        service.state.shown[badge] = shown;
        service.state.saving[badge] = true;
        apply(badge);
        return pamService.setBadgeShown(badge, shown)['catch'](function badgeFailed(error) {
            service.state.shown[badge] = !shown;
            apply(badge);
            throw error;
        })['finally'](function badgeSaved() {
            delete service.state.saving[badge];
        });
    };

    service.clear = function clear() {
        service.state.loaded = false;
        service.state.available = { approvals : false, rotations : false };
        angular.forEach(BADGES, function stopBadge(counter) {
            counter.stop();
        });
    };

    return service;

}]);
