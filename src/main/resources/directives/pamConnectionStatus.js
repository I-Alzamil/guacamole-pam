/**
 * Request status of a connection on the home screen. For Accounts,
 * "Currently in use by N users" (Guacamole counts open sessions there, which
 * Accounts never have, so this counts the users holding the password, using
 * Guacamole's own wording and styling). For any connection needing a
 * request, a label when the user holds it, awaits approval, or has it
 * approved ahead of time, which opens the request dialog (to release, or
 * cancel) instead of the connection.
 * Placed by templates/pamConnectionStatus.html.
 */
angular.module('guacPam').directive('pamConnectionStatus', [function pamConnectionStatus() {

    return {
        restrict   : 'E',
        scope      : {
            item : '<'
        },
        template   : '<span class="activeUserCount" ng-if="count()"'
                   + '      translate="HOME.INFO_ACTIVE_USER_COUNT"'
                   + '      translate-values="{USERS: count()}"></span>'
                   + '<span class="pam-connection-status" ng-class="status()" ng-if="status()"'
                   + '      role="button" tabindex="0" title="{{ \'PAM.HOME.HELP_MANAGE\' | translate }}"'
                   + '      ng-click="open($event)" ng-keydown="openOnKey($event)">{{ label() }}</span>',
        controller : ['$scope', '$injector', function pamConnectionStatusController($scope, $injector) {

            var $filter           = $injector.get('$filter');
            var pamRequestService = $injector.get('pamRequestService');
            var pamService        = $injector.get('pamService');

            var entry = function entry() {
                return $scope.item ? pamRequestService.getEntry($scope.item.identifier) : null;
            };

            $scope.count = function count() {
                return $scope.item ? pamRequestService.getAccountHolders($scope.item.identifier) : 0;
            };

            /**
             * "held", "pending" or "reserved" (also the label's class), or
             * null.
             */
            $scope.status = function status() {
                var current = entry();
                if (!current)
                    return null;
                if (current.mine && (!current.expires || current.expires > pamService.now()))
                    return 'held';
                if (current.pending)
                    return 'pending';
                if (current.reservation && current.reservation.ends > pamService.now())
                    return 'reserved';
                return null;
            };

            $scope.label = function label() {
                var current = entry();
                var translate = $filter('translate');
                if ($scope.status() === 'pending')
                    return translate('PAM.HOME.TEXT_PENDING');
                if ($scope.status() === 'reserved')
                    return translate('PAM.HOME.TEXT_RESERVED',
                            { STARTS : $filter('date')(current.reservation.starts, 'short') });
                return translate(current.account ? 'PAM.HOME.TEXT_CHECKED_OUT' : 'PAM.HOME.TEXT_ACCESS_HELD',
                        { EXPIRES : $filter('date')(current.expires, 'shortTime') });
            };

            /**
             * Opens the request dialog. The label is inside the connection's
             * link, so opening the connection itself is prevented.
             */
            $scope.open = function open($event) {
                $event.preventDefault();
                $event.stopPropagation();
                pamRequestService.open($scope.item.identifier);
            };

            $scope.openOnKey = function openOnKey($event) {
                if ($event.key === 'Enter' || $event.key === ' ')
                    $scope.open($event);
            };

        }]
    };

}]);
