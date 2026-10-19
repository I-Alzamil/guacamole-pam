/**
 * A count needing the user's attention, hidden when zero: requests awaiting
 * their approval (kind="approvals", the default, yellow) or failed password
 * rotations (kind="rotations", red, for administrators). Shown as a badge
 * linking to the matching tab (next to the user menu), or, with
 * plain="true", as a quiet "(N)" inside a tab label.
 */
angular.module('guacPam').directive('pamApprovalBadge', [function pamApprovalBadge() {

    /**
     * Counter, tab and tooltip of each kind of badge.
     */
    var KINDS = {
        approvals : { service : 'pamApprovalBadge', url : '#/settings/pam-approvals', text : 'PAM_APPROVALS.INFO_BADGE' },
        rotations : { service : 'pamRotationBadge', url : '#/settings/pam-rotation',  text : 'PAM.INFO_BADGE_FAILURES' }
    };

    return {
        restrict   : 'E',
        scope      : {
            plain : '@',
            kind  : '@'
        },
        template   : '<span class="pam-tab-count {{ kindName }}" ng-if="plain === \'true\'" ng-show="badge.count()">'
                   + '({{ badge.count() }})</span>'
                   + '<a class="pam-badge {{ kindName }}" ng-if="plain !== \'true\'" ng-show="badge.count()" ng-href="{{ config.url }}"'
                   + '   title="{{ config.text | translate:{ COUNT: badge.count() } }}">'
                   + '{{ badge.count() }}</a>',
        controller : ['$scope', '$injector', function pamApprovalBadgeController($scope, $injector) {
            // The kind is a constant attribute, known once linked
            $scope.kindName = KINDS[$scope.kind] ? $scope.kind : 'approvals';
            $scope.config = KINDS[$scope.kindName];
            $scope.badge = $injector.get($scope.config.service);
        }]
    };

}]);
