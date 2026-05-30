from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404

from organization.models import Organization, OrganizationMember


# Create your views here.
@login_required(login_url='/auth/login/')
def workspaceAdmin(request, org_id):
    org = Organization.objects.get(id=org_id)
    membership = org.members.filter(user=request.user).first()
    current_member_count = OrganizationMember.objects.filter(org=org).count()
    active_projects_count = 2
    return render(request, 'overview.html', {'org': org, 'membership': membership, 'current_member_count': current_member_count, 'active_projects_count': active_projects_count})



@login_required
def projects(request, org_id):
    org = get_object_or_404(Organization, id=org_id)

    # 2. Check if the user belongs to the Organization at all
    membership = org.members.filter(user=request.user).first()
    if not membership:
        return render(request, 'errors/403.html', {'message': "You aren't a member of this organization."}, status=403)

    # 3. Pull all active projects inside this organization for the dropdown selector
    all_projects = org.projects.filter(is_active=True)

    # 4. Determine the currently active project
    # Looks for a '?project_id=...' in the URL, falls back to the newest project, or returns None
    project_id = request.GET.get('project_id')
    if project_id:
        current_project = all_projects.filter(id=project_id).first()
    else:
        current_project = all_projects.first()  # Default to the first available project

    # 5. Calculate Octal Permissions for the Logged-In User
    # Default everything to False in case there are no projects created yet
    can_read_project = False
    can_write_project = False
    can_execute_project = False

    if current_project:
        can_read_project = current_project.check_permission(request.user, 'read')
        can_write_project = current_project.check_permission(request.user, 'write')
        can_execute_project = current_project.check_permission(request.user, 'execute')

    # 6. Organization-level global rules (e.g., Who can create a whole new project?)
    # Usually Admins and Project Managers can create projects, regular members or viewers cannot.
    can_create_project = membership.role in ['admin', 'project_manager']

    # 7. Package-level limits check (Optional Guardrail)
    # If they hit their max active project limit, force 'can_create_project' to False
    if all_projects.count() >= org.package.max_projects and org.package.max_projects != -1:
        can_create_project = False

    context = {
        'org': org,
        'membership': membership,
        'project': current_project,
        'all_projects': all_projects,

        # Permission Gates utilized directly by your template layout
        'can_read_project': can_read_project,
        'can_write_project': can_write_project,
        'can_execute_project': can_execute_project,
        'can_create_project': can_create_project,
    }

    return render(request, 'projects.html', context)


def storage(request, org_id):
    org = Organization.objects.get(id=org_id)
    membership = org.members.filter(user=request.user).first()
    return render(request, 'storage.html', {'org': org, 'membership': membership})