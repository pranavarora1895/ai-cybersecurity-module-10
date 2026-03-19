import secrets

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand

from archiver.models import Archive


def generate_strong_password(length=16):
    return secrets.token_urlsafe(length)


class Command(BaseCommand):
    help = "Seeds the database with initial users and sample data"

    def handle(self, *args, **kwargs):
        self.stdout.write("Seeding data...")

        Archive.objects.all().delete()
        User.objects.filter(username__in=["admin", "alice", "bob"]).delete()

        admin_pw = generate_strong_password()
        alice_pw = generate_strong_password()
        bob_pw = generate_strong_password()

        if not User.objects.filter(username="admin").exists():
            User.objects.create_superuser("admin", "admin@example.com", admin_pw)

        alice = User.objects.create_user("alice", "alice@example.com", alice_pw)
        bob = User.objects.create_user("bob", "bob@example.com", bob_pw)

        self.stdout.write(f"Created admin with password: {admin_pw}")
        self.stdout.write(f"Created alice with password: {alice_pw}")
        self.stdout.write(f"Created bob with password: {bob_pw}")
        self.stdout.write(self.style.WARNING("Save these passwords — they are randomly generated and won't be shown again."))

        Archive.objects.create(
            user=alice,
            url="https://example.com",
            title="Example Domain",
            content="<html><body><h1>Example Domain</h1><p>This domain is for use in illustrative examples in documents.</p></body></html>",
            notes="Just a regular example site. Nothing to see here.",
        )

        Archive.objects.create(
            user=alice,
            url="https://cats-info.com",
            title="All About Cats",
            content="<html><body><h1>Cats</h1><p>Cats are small carnivorous mammals. They are the only domesticated species in the family Felidae.</p></body></html>",
            notes="Interesting article about cats for my research.",
        )

        Archive.objects.create(
            user=bob,
            url="https://bob-blog.com",
            title="Bob's Blog Drafts",
            content="<html><body><h1>Welcome to Bob's Blog</h1><p>These are my private thoughts.</p></body></html>",
            notes="Draft for my next post about how much I like security.",
        )

        self.stdout.write(
            self.style.SUCCESS(
                "Successfully seeded database with users and vulnerable archives!"
            )
        )
