/**
 * The "Can approve requests" permission of the user and user group editors,
 * shown as rows of the editor's permissions table, like the system
 * permissions. Placed after the system permissions by
 * templates/pamApprovalPermissionsPatch.html, it moves its rows into that
 * table once rendered (patches cannot insert table rows themselves), or
 * keeps them in an "Approvals" section of its own if there is none. What it
 * covers is chosen with the "Approve" checkboxes of the editor's connections
 * list. The server only accepts changes from administrators.
 */
angular.module('guacPam').directive('pamApprovalPermissions', [function pamApprovalPermissions() {

    /**
     * Data source whose users and groups can approve.
     */
    var DATA_SOURCE = 'postgresql';

    return {
        restrict    : 'E',
        scope       : {
            attributes : '<',
            group      : '<',
            editable   : '<',
            dataSource : '<'
        },
        templateUrl : 'app/ext/pam/templates/pamApprovalPermissions.html',
        link        : function linkApprovalPermissions($scope, $element) {

            /**
             * Moves the rows into the permissions table of the system
             * permission editor next to this one, once it has rendered.
             */
            var merge = function merge() {

                var editor = $element[0].previousElementSibling;
                while (editor && editor.tagName.toLowerCase() !== 'system-permission-editor')
                    editor = editor.previousElementSibling;

                var target = editor && editor.querySelector('table.properties tbody');
                var rows = $element[0].querySelectorAll('tr.pam-approval-row');
                if (!target || !rows.length)
                    return false;

                angular.forEach(rows, function moveRow(row) {
                    target.appendChild(row);
                });
                $scope.merged = true;
                return true;

            };

            $scope.merged = false;

            // Both templates load asynchronously; watch until both are there
            var parent = $element[0].parentNode;
            var observer = null;
            var tryMerge = function tryMerge() {
                if (!$scope.merged && merge()) {
                    if (observer)
                        observer.disconnect();
                    $scope.$evalAsync();
                }
            };

            if (parent) {
                observer = new MutationObserver(tryMerge);
                observer.observe(parent, { childList : true, subtree : true });
            }
            $scope.$evalAsync(tryMerge);

            $scope.$on('$destroy', function approvalPermissionsDestroyed() {
                if (observer)
                    observer.disconnect();
                angular.forEach(document.querySelectorAll('tr.pam-approval-row'), function removeRow(row) {
                    if (!$element[0].contains(row))
                        row.parentNode.removeChild(row);
                });
            });

        },
        controller  : ['$scope', '$injector', function pamApprovalPermissionsController($scope, $injector) {

            var pamApprovalSelection = $injector.get('pamApprovalSelection');

            $scope.selection = pamApprovalSelection;

            $scope.isApplicable = function isApplicable() {
                return $scope.dataSource === DATA_SOURCE && !!$scope.attributes;
            };

            /**
             * Getter/setter of the checkbox.
             */
            $scope.approver = function approver(value) {
                if (arguments.length)
                    pamApprovalSelection.setApprover(value);
                return pamApprovalSelection.isApprover();
            };

            // The user or group is loaded after the editor appears
            $scope.$watchGroup(['attributes', 'editable', 'dataSource'], function bindSelection() {
                if ($scope.isApplicable())
                    pamApprovalSelection.bind($scope.attributes, $scope.editable);
                else
                    pamApprovalSelection.unbind();
            });

            $scope.$on('$destroy', function permissionsDestroyed() {
                pamApprovalSelection.unbind();
            });

        }]
    };

}]);
