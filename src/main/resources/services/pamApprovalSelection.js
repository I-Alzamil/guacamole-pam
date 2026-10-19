/**
 * The approval permission of the user or group being edited, shared between
 * the "Can approve requests" checkbox (pamApprovalPermissions) and the
 * "Approve" checkboxes added to each connection and connection group of the
 * editor's connections list (pamApproveChoice). Changes are written into the
 * attributes of the user or group, saved by the editor's own Save button.
 */
angular.module('guacPam').factory('pamApprovalSelection', [function pamApprovalSelection() {

    var APPROVER = 'pam-approver';
    var CONNECTIONS = 'pam-approver-connections';
    var GROUPS = 'pam-approver-connection-groups';

    var service = {};

    /**
     * Attributes of the user or group being edited, or null.
     */
    var attributes = null;

    var editable = false;

    var parse = function parse(value) {
        try {
            var identifiers = value ? JSON.parse(value) : [];
            return angular.isArray(identifiers) ? identifiers : [];
        }
        catch (e) {
            return [];
        }
    };

    var write = function write(name, identifiers) {
        attributes[name] = identifiers.length ? JSON.stringify(identifiers) : null;
    };

    /**
     * Starts editing the permission held in the given attributes.
     */
    service.bind = function bind(boundAttributes, canEdit) {
        attributes = boundAttributes;
        editable = !!canEdit;
    };

    service.unbind = function unbind() {
        attributes = null;
    };

    service.isEditable = function isEditable() {
        return !!attributes && editable;
    };

    /**
     * Whether "Can approve requests" is granted.
     */
    service.isApprover = function isApprover() {
        return !!attributes && attributes[APPROVER] === 'true';
    };

    service.setApprover = function setApprover(approver) {
        if (!attributes)
            return;
        attributes[APPROVER] = approver ? 'true' : null;

        // Without the permission, the selection would grant nothing
        if (!approver) {
            attributes[CONNECTIONS] = null;
            attributes[GROUPS] = null;
        }
    };

    /**
     * Whether requests of the given connection ("connection") or of every
     * connection within the given connection group ("group") may be approved.
     */
    service.isSelected = function isSelected(type, identifier) {
        return !!attributes && parse(attributes[type === 'group' ? GROUPS : CONNECTIONS]).indexOf(identifier) !== -1;
    };

    service.setSelected = function setSelected(type, identifier, selected) {

        if (!attributes)
            return;

        var name = type === 'group' ? GROUPS : CONNECTIONS;
        var identifiers = parse(attributes[name]).filter(function others(other) {
            return other !== identifier;
        });

        if (selected)
            identifiers.push(identifier);

        write(name, identifiers);

    };

    /**
     * Number of connections and connection groups selected.
     */
    service.count = function count() {
        return attributes ? parse(attributes[CONNECTIONS]).length + parse(attributes[GROUPS]).length : 0;
    };

    return service;

}]);
