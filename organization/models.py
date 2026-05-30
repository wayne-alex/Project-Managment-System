import uuid
from django.db import models
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey
from django.core.exceptions import ValidationError
from authentication.models import User


class SubscriptionPackage(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    is_featured = models.BooleanField(default=False)
    name = models.CharField(max_length=50, unique=True)
    display_name = models.CharField(max_length=100)
    price_monthly = models.DecimalField(max_digits=8, decimal_places=2, default=0.00)
    max_members = models.IntegerField(default=5)
    max_projects = models.IntegerField(default=3)
    storage_gb = models.BigIntegerField(default=1)
    has_gantt_chart = models.BooleanField(default=False)
    has_burndown_reports = models.BooleanField(default=False)
    has_sso_saml = models.BooleanField(default=False)
    has_dedicated_support = models.BooleanField(default=False)
    has_sla_guarantee = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def description(self):
        descriptions = {
            'free': "Perfect for small teams and side projects.",
            'pro': "For growing teams that need the full toolkit.",
            'enterprise': "For large organizations with custom requirements."
        }
        return descriptions.get(self.name.lower(), "")

    @property
    def members_display(self):
        return "Unlimited members" if self.max_members == -1 else f"Up to {self.max_members} members"

    @property
    def projects_display(self):
        return "Unlimited projects" if self.max_projects == -1 else f"{self.max_projects} active projects"

    @property
    def storage_display(self):
        return "Unlimited storage" if self.storage_gb >= 1000 or self.storage_gb == -1 else f"{self.storage_gb}GB storage"

    class Meta:
        db_table = "subscription_packages"

    def __str__(self):
        return self.display_name


class Organization(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    domain = models.CharField(max_length=100, unique=True, blank=True, null=True)
    package = models.ForeignKey(SubscriptionPackage, on_delete=models.PROTECT, related_name="organizations")
    timezone = models.CharField(max_length=50, default="UTC")
    logo = models.ImageField(upload_to="org_logos/", null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "organizations"

    def __str__(self):
        return self.name


class OrganizationMember(models.Model):
    ROLE_CHOICES = [
        ("admin", "Admin"),
        ("project_manager", "Project Manager"),
        ("member", "Member"),
        ("viewer", "Viewer"),
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="memberships")
    org = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="members")
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default="member")
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "organization_members"
        unique_together = ("user", "org")

    def __str__(self):
        return f"{self.user.email} @ {self.org.name}"


class AuditLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="audit_logs")
    actor = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name="actions_logged")
    action_key = models.CharField(max_length=100)
    description = models.TextField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=500, null=True, blank=True)
    content_type = models.ForeignKey(ContentType, on_delete=models.SET_NULL, null=True, blank=True)
    object_id = models.CharField(max_length=255, null=True, blank=True)
    target_object = GenericForeignKey('content_type', 'object_id')
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "organization_audit_logs"
        ordering = ["-timestamp"]

    def __str__(self):
        return f"[{self.action_key}] at {self.timestamp} by {self.actor}"


# ─────────────────────────────────────────────
#  PERMISSION SYSTEM
#  Bit values (NOT standard Linux):
#    4 = write   → change task status
#    2 = read    → view task details
#    1 = execute → change project structure
#                  (add members, set timeline, etc.)
#
#  Common octal combos:
#    7 (4+2+1) = full access
#    6 (4+2)   = write + read (no structural changes)
#    3 (2+1)   = read + execute
#    2         = read only
#    1         = execute only
#    0         = no access
#
#  Three-digit octal  XYZ  where:
#    X = owner digit   (project creator — always has execute bit forced on)
#    Y = group digit   (project members)
#    Z = others digit  (org members not in this project)
# ─────────────────────────────────────────────

PERM_WRITE   = 4   # change task status
PERM_READ    = 2   # view task details
PERM_EXECUTE = 1   # change project structure


def validate_permission_octal(value: int):
    """Each digit must be 0-7 and the value must be a valid 3-digit octal (0–777)."""
    if not (0 <= value <= 777):
        raise ValidationError(f"Permission {value} out of range. Must be 0–777.")
    digits = [int(d) for d in str(value).zfill(3)]
    if any(d > 7 for d in digits):
        raise ValidationError(f"Each permission digit must be 0–7. Got {value}.")


class PermissionMixin:
    """
    Shared helper methods for any model that stores a 3-digit permission octal.
    Models must have a `permissions` integer field.
    """

    def _digit(self, position: int) -> int:
        """
        Extract owner (0), group (1), or others (2) digit from the octal.
        e.g. permissions=764 → digits [7, 6, 4]
        """
        return int(str(self.permissions).zfill(3)[position])

    @property
    def owner_digit(self) -> int:
        return self._digit(0)

    @property
    def group_digit(self) -> int:
        return self._digit(1)

    @property
    def others_digit(self) -> int:
        return self._digit(2)

    def _has_bit(self, digit: int, bit: int) -> bool:
        return bool(digit & bit)

    def _digit_for_user(self, user, owner_id, group_user_ids: list) -> int:
        if user.id == owner_id:
            return self.owner_digit
        if user.id in group_user_ids:
            return self.group_digit
        return self.others_digit

    def can_read(self, user, owner_id, group_user_ids: list) -> bool:
        """Can view task details."""
        return self._has_bit(self._digit_for_user(user, owner_id, group_user_ids), PERM_READ)

    def can_write(self, user, owner_id, group_user_ids: list) -> bool:
        """Can change task status."""
        return self._has_bit(self._digit_for_user(user, owner_id, group_user_ids), PERM_WRITE)

    def can_execute(self, user, owner_id, group_user_ids: list) -> bool:
        """Can change project structure (add members, set timeline, etc.)."""
        return self._has_bit(self._digit_for_user(user, owner_id, group_user_ids), PERM_EXECUTE)

    def permission_summary(self) -> dict:
        """Human-readable breakdown of all three digit positions."""
        def breakdown(digit):
            return {
                "octal": digit,
                "write": bool(digit & PERM_WRITE),
                "read": bool(digit & PERM_READ),
                "execute": bool(digit & PERM_EXECUTE),
                "label": (
                    ("w" if digit & PERM_WRITE else "-") +
                    ("r" if digit & PERM_READ else "-") +
                    ("x" if digit & PERM_EXECUTE else "-")
                ),
            }
        return {
            "raw": self.permissions,
            "owner":  breakdown(self.owner_digit),
            "group":  breakdown(self.group_digit),
            "others": breakdown(self.others_digit),
        }


# ─────────────────────────────────────────────
#  PROJECT
# ─────────────────────────────────────────────

class Project(PermissionMixin, models.Model):
    """
    A project belongs to one organization and groups tasks together.

    Permission octal (custom, NOT Linux):
      4 = write   → members who can change task statuses
      2 = read    → members who can view task details
      1 = execute → members who can alter project structure
                    (invite/remove members, set timeline, rename, etc.)

    The owner always has execute forced on (owner_digit | 1) at save time
    so no owner can accidentally lock themselves out of their own project.

    Default 762:
      owner  = 7 (write+read+execute)
      group  = 6 (write+read, no structural changes)
      others = 2 (read-only, cannot change status or structure)
    """

    STATUS_CHOICES = [
        ("planning",    "Planning"),
        ("active",      "Active"),
        ("on_hold",     "On Hold"),
        ("completed",   "Completed"),
        ("archived",    "Archived"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    org = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="projects",
    )
    owner = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name="owned_projects",
        help_text="The user who created the project. Always retains execute bit.",
    )
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="planning")
    color = models.CharField(max_length=7, default="#5b6eff", help_text="Hex color for UI display.")

    # Timeline (execute-gated — only users with bit 1 can modify these)
    start_date = models.DateField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)

    # Permission octal stored as integer (0–777).
    # Default 762: owner=full, group=write+read, others=read-only.
    permissions = models.PositiveSmallIntegerField(
        default=762,
        validators=[validate_permission_octal],
        help_text=(
            "3-digit octal: XYZ where X=owner, Y=group, Z=others. "
            "Bits: 4=write(task status), 2=read(view), 1=execute(structure). "
            "Owner execute bit is always forced on at save."
        ),
    )

    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "projects"
        ordering = ["-created_at"]
        constraints = [
            # Org limit is enforced in the service layer using package.max_projects,
            # but we add a DB-level uniqueness guard on name within the same org.
            models.UniqueConstraint(fields=["org", "name"], name="unique_project_name_per_org"),
        ]

    def save(self, *args, **kwargs):
        # ENFORCE: owner digit must always carry the execute bit (1).
        # This prevents an owner from revoking their own structural access.
        digits = list(str(self.permissions).zfill(3))
        owner_digit = int(digits[0])
        if not (owner_digit & PERM_EXECUTE):
            owner_digit |= PERM_EXECUTE         # force bit 1 on
            digits[0] = str(owner_digit)
            self.permissions = int("".join(digits))
        super().save(*args, **kwargs)

    def get_member_user_ids(self) -> list:
        """Returns list of user IDs who are explicit project members (the 'group')."""
        return list(self.project_members.values_list("user_id", flat=True))

    def check_permission(self, user: User, action: str) -> bool:
        """
        Convenience method. action must be 'read', 'write', or 'execute'.
        Raises ValueError on unknown action.
        """
        group_ids = self.get_member_user_ids()
        if action == "read":
            return self.can_read(user, self.owner_id, group_ids)
        if action == "write":
            return self.can_write(user, self.owner_id, group_ids)
        if action == "execute":
            return self.can_execute(user, self.owner_id, group_ids)
        raise ValueError(f"Unknown action '{action}'. Use 'read', 'write', or 'execute'.")

    def __str__(self):
        return f"{self.name} [{self.org.name}] chmod {self.permissions}"


# ─────────────────────────────────────────────
#  PROJECT MEMBER  (the "group" in our octal)
# ─────────────────────────────────────────────

class ProjectMember(models.Model):
    """
    Explicit membership record that places a user into the 'group' digit
    of the project's permission octal.

    The `can_execute` flag lets individual members be granted structural
    access (bit 1) even when the group digit doesn't carry it — useful
    when group=6 (write+read) but one member should also manage members/timeline.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name="project_members",
    )
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="project_memberships",
    )

    # Per-member execute override:
    # If True, this member can perform structural changes regardless of
    # whether the group digit carries bit 1.
    can_execute_override = models.BooleanField(
        default=False,
        help_text=(
            "Grant execute (structure) permission to this member individually, "
            "even if the project group digit does not include bit 1."
        ),
    )

    invited_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name="project_invites_sent",
    )
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "project_members"
        unique_together = ("project", "user")

    def __str__(self):
        return f"{self.user.email} → {self.project.name}"

    def effective_digit(self) -> int:
        """
        Returns the effective permission digit for this member.
        Starts from the project's group digit, then ORs in execute if overridden.
        """
        digit = self.project.group_digit
        if self.can_execute_override:
            digit |= PERM_EXECUTE
        return digit

    def effective_permissions(self) -> dict:
        """Human-readable summary of what this member can actually do."""
        digit = self.effective_digit()
        return {
            "digit": digit,
            "read":    bool(digit & PERM_READ),
            "write":   bool(digit & PERM_WRITE),
            "execute": bool(digit & PERM_EXECUTE),
            "label": (
                ("w" if digit & PERM_WRITE else "-") +
                ("r" if digit & PERM_READ else "-") +
                ("x" if digit & PERM_EXECUTE else "-")
            ),
        }


# ─────────────────────────────────────────────
#  PROJECT TIMELINE
#  (execute-gated: only users with bit 1 can create/modify)
# ─────────────────────────────────────────────

class ProjectTimeline(models.Model):
    """
    Milestone / phase entries for a project's Gantt or timeline view.
    Creating, editing, or deleting these requires execute permission (bit 1).
    """

    MILESTONE_TYPE_CHOICES = [
        ("milestone", "Milestone"),
        ("phase",     "Phase"),
        ("deadline",  "Deadline"),
        ("sprint",    "Sprint"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name="timeline_entries",
    )
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name="timeline_entries_created",
    )
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    entry_type = models.CharField(max_length=20, choices=MILESTONE_TYPE_CHOICES, default="milestone")
    start_date = models.DateField()
    end_date = models.DateField(null=True, blank=True)
    color = models.CharField(max_length=7, default="#06d6a0")
    is_completed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "project_timeline"
        ordering = ["start_date"]

    def __str__(self):
        return f"{self.title} ({self.project.name})"


# ─────────────────────────────────────────────
#  TASK
#  (each task carries its own permission octal,
#   defaulting to the project's octal at creation)
# ─────────────────────────────────────────────

class Task(PermissionMixin, models.Model):
    """
    A task belongs to a project and inherits the project's permission octal
    by default, but can be overridden per-task for fine-grained control.

    Permission semantics on a task:
      write   (4) → change this task's status
      read    (2) → view this task's detail
      execute (1) → not used at task level; reserved / future use
    """

    STATUS_CHOICES = [
        ("todo",        "To Do"),
        ("in_progress", "In Progress"),
        ("in_review",   "In Review"),
        ("done",        "Done"),
        ("cancelled",   "Cancelled"),
    ]

    PRIORITY_CHOICES = [
        ("low",      "Low"),
        ("medium",   "Medium"),
        ("high",     "High"),
        ("critical", "Critical"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name="tasks",
    )
    owner = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name="owned_tasks",
        help_text="User who created the task. Uses owner digit of task permissions.",
    )
    assignee = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name="assigned_tasks",
    )

    title = models.CharField(max_length=300)
    description = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="todo")
    priority = models.CharField(max_length=20, choices=PRIORITY_CHOICES, default="medium")

    due_date = models.DateField(null=True, blank=True)
    estimated_hours = models.DecimalField(max_digits=6, decimal_places=2, null=True, blank=True)

    # Task-level permission octal.
    # Defaults to 0 meaning "inherit from project" — resolved at query time.
    # Set explicitly to override project-level permissions for this specific task.
    permissions = models.PositiveSmallIntegerField(
        default=0,
        validators=[validate_permission_octal],
        help_text=(
            "Task-level chmod override. 0 = inherit from project. "
            "Bits: 4=write(change status), 2=read(view detail), 1=execute(reserved)."
        ),
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "tasks"
        ordering = ["-created_at"]

    def resolved_permissions(self) -> int:
        """
        Returns the effective permission octal for this task.
        Falls back to the parent project's octal when task permissions = 0.
        """
        return self.permissions if self.permissions != 0 else self.project.permissions

    def _resolved_mixin_permissions(self):
        """Override PermissionMixin to use resolved permissions (not raw self.permissions)."""
        return self.resolved_permissions()

    def _digit(self, position: int) -> int:
        return int(str(self.resolved_permissions()).zfill(3)[position])

    def check_permission(self, user: User, action: str) -> bool:
        """
        Checks task-level permission for a user.
        Group = project members. Owner = task.owner.
        """
        group_ids = self.project.get_member_user_ids()

        # Also check per-member execute override for execute checks
        if action == "execute":
            try:
                membership = self.project.project_members.get(user=user)
                if membership.can_execute_override:
                    return True
            except ProjectMember.DoesNotExist:
                pass

        if action == "read":
            return self.can_read(user, self.owner_id, group_ids)
        if action == "write":
            return self.can_write(user, self.owner_id, group_ids)
        if action == "execute":
            return self.can_execute(user, self.owner_id, group_ids)
        raise ValueError(f"Unknown action '{action}'. Use 'read', 'write', or 'execute'.")

    def __str__(self):
        return f"{self.title} [{self.status}] chmod {self.resolved_permissions()}"


# ─────────────────────────────────────────────
#  TASK COMMENT
#  (read-gated: only users who can read the task can comment)
# ─────────────────────────────────────────────

class TaskComment(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    task = models.ForeignKey(Task, on_delete=models.CASCADE, related_name="comments")
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name="task_comments")
    body = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "task_comments"
        ordering = ["created_at"]

    def __str__(self):
        return f"Comment by {self.author.email} on {self.task.title}"


# ─────────────────────────────────────────────
#  TASK STATUS HISTORY
#  Tracks every status change (write-gated action)
# ─────────────────────────────────────────────

class TaskStatusHistory(models.Model):
    """
    Immutable log of every task status transition.
    A new row is written each time a user exercises their write (4) bit.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    task = models.ForeignKey(Task, on_delete=models.CASCADE, related_name="status_history")
    changed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name="status_changes_made")
    from_status = models.CharField(max_length=20)
    to_status = models.CharField(max_length=20)
    changed_at = models.DateTimeField(auto_now_add=True)
    note = models.TextField(blank=True)

    class Meta:
        db_table = "task_status_history"
        ordering = ["-changed_at"]

    def __str__(self):
        return f"{self.task.title}: {self.from_status} → {self.to_status}"