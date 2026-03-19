import datetime
from datetime import timezone

import jwt
import requests
from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.db import connection
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render

from .llm_utils import query_llm
from .models import Archive

# Create your views here.


def register(request):
    if request.method == "POST":
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, "Registration successful!")
            return redirect("dashboard")
    else:
        form = UserCreationForm()
    return render(request, "archiver/register.html", {"form": form})


@login_required
def dashboard(request):
    return render(request, "archiver/dashboard.html")


@login_required
def generate_token(request):
    SECRET = "do_not_share_this"

    payload = {
        "user_id": request.user.id,
        "username": request.user.username,
        "exp": datetime.datetime.now(timezone.utc) + datetime.timedelta(days=1),
    }

    # jwt.encode returns a string in PyJWT >= 2.0.0
    token = jwt.encode(payload, SECRET, algorithm="HS256")

    return JsonResponse(
        {"token": token, "note": "This token was signed with a hardcoded secret!"}
    )


@login_required
def archive_list(request):
    archives = Archive.objects.filter(user=request.user).order_by("-created_at")
    return render(request, "archiver/archive_list.html", {"archives": archives})


@login_required
def add_archive(request):
    if request.method == "POST":
        url = request.POST.get("url")
        notes = request.POST.get("notes")

        if url:
            try:
                response = requests.get(url, timeout=10)
                title = "No Title Found"
                if "<title>" in response.text:
                    try:
                        title = (
                            response.text.split("<title>", 1)[1]
                            .split("</title>", 1)[0]
                            .strip()
                        )
                    except IndexError:
                        pass

                Archive.objects.create(
                    user=request.user,
                    url=url,
                    title=title,
                    content=response.text,
                    notes=notes,
                )
                messages.success(request, "URL archived successfully!")
                return redirect("archive_list")
            except Exception as e:
                messages.error(request, f"Failed to archive URL: {str(e)}")

    return render(request, "archiver/add_archive.html")


@login_required
def view_archive(request, archive_id):
    archive = get_object_or_404(Archive, pk=archive_id, user=request.user)
    return render(request, "archiver/view_archive.html", {"archive": archive})


@login_required
def edit_archive(request, archive_id):
    archive = get_object_or_404(Archive, pk=archive_id, user=request.user)

    if request.method == "POST":
        archive.notes = request.POST.get("notes")
        archive.save()
        messages.success(request, "Archive updated successfully!")
        return redirect("archive_list")

    return render(request, "archiver/edit_archive.html", {"archive": archive})


@login_required
def delete_archive(request, archive_id):
    archive = get_object_or_404(Archive, pk=archive_id, user=request.user)

    if request.method == "POST":
        archive.delete()
        messages.success(request, "Archive deleted successfully!")
        return redirect("archive_list")

    return render(request, "archiver/delete_archive.html", {"archive": archive})


@login_required
def search_archives(request):
    query = request.GET.get("q", "")
    results = []

    if query:
        results = Archive.objects.filter(
            user=request.user,
            title__icontains=query,
        ).select_related("user").order_by("-created_at")

    return render(request, "archiver/search.html", {"results": results, "query": query})


@login_required
def ask_database(request):
    answer = None
    sql_query = None
    user_input = request.POST.get("prompt", "")

    if request.method == "POST" and user_input:
        # Schema info for the LLM
        schema_info = """
        Table: archiver_archive
        Columns: id, title, url, content, notes, created_at, user_id
        """

        system_prompt = f"""
        You are a SQL expert. Convert the user's natural language query into a raw SQLite SQL query.
        The table name is 'archiver_archive'.
        Do not explain. Return ONLY the SQL query.
        Current User ID: {request.user.id}
        Schema:
        {schema_info}
        """

        # Get SQL from LLM
        sql_query = query_llm(user_input, system_instruction=system_prompt).strip()

        # Clean up markdown code blocks if present
        if "```sql" in sql_query:
            sql_query = sql_query.split("```sql")[1].split("```")[0].strip()
        elif "```" in sql_query:
            sql_query = sql_query.split("```")[1].strip()

        try:
            with connection.cursor() as cursor:
                cursor.execute(sql_query)
                if cursor.description:
                    columns = [col[0] for col in cursor.description]
                    results = [dict(zip(columns, row)) for row in cursor.fetchall()]
                    answer = results
                else:
                    answer = "Query executed successfully (no results returned)."
        except Exception as e:
            answer = f"Error executing SQL: {str(e)}"

    return render(
        request,
        "archiver/ask_database.html",
        {"answer": answer, "sql_query": sql_query, "prompt": user_input},
    )


@login_required
def export_summary(request):
    if request.method == "POST":
        topic = request.POST.get("topic")
        filename_hint = request.POST.get("filename_hint")

        # Prompt for LLM to generate summary content
        content_prompt = f"Write a short summary about: {topic}"
        summary_content = query_llm(content_prompt)

        # Prompt for LLM to determine filename
        path_prompt = f"""
        Generate a filename for a summary about '{topic}'.
        The user suggested: '{filename_hint}'.
        Return ONLY the full file path.
        Base directory is: ./exported_summaries/
        """
        file_path = query_llm(path_prompt).strip()

        # Clean up if LLM wraps in quotes or code blocks
        if "```" in file_path:
            import re

            match = re.search(r"```(?:\w+)?\s*(.*?)\s*```", file_path, re.DOTALL)
            if match:
                file_path = match.group(1).strip()
            else:
                # Fallback if regex fails or structure is weird
                parts = file_path.split("```")
                if len(parts) > 1:
                    file_path = parts[1].strip()

        file_path = file_path.strip("'\"")

        try:
            with open(file_path, "w") as f:
                f.write(summary_content)

            messages.success(request, f"Summary written to: {file_path}")
        except Exception as e:
            messages.error(request, f"File Write Error: {str(e)}")

    return render(request, "archiver/export_summary.html")


@login_required
def enrich_archive(request, archive_id):
    archive = get_object_or_404(Archive, pk=archive_id, user=request.user)
    llm_response = None

    if request.method == "POST":
        user_instruction = request.POST.get(
            "instruction", "Summarize this content and find related links."
        )

        system_prompt = """
        You are an AI assistant that enriches archived content.
        You can fetch external data if explicitly requested or if the content implies it.
        """

        prompt = f"""
        User Instruction: {user_instruction}

        Archive Content:
        {archive.content}

        Archive Notes:
        {archive.notes}
        """

        tools = [
            {
                "type": "function",
                "function": {
                    "name": "fetch_url",
                    "description": "Fetch data from a URL",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "description": "The URL to fetch",
                            }
                        },
                        "required": ["url"],
                    },
                },
            }
        ]

        # response is now a message dict when tools are provided
        message = query_llm(prompt, system_instruction=system_prompt, tools=tools)

        # Check for tool calls
        if message.get("tool_calls"):
            tool_calls = message["tool_calls"]
            llm_response = f"LLM decided to use tools:\n{tool_calls}\n\n"

            for tool in tool_calls:
                if tool["function"]["name"] == "fetch_url":
                    url_to_fetch = tool["function"]["arguments"]["url"]
                    try:
                        requests.get(url_to_fetch, timeout=5)
                        llm_response += f"Successfully fetched: {url_to_fetch}\n"
                    except Exception as e:
                        llm_response += f"Failed to fetch {url_to_fetch}: {str(e)}\n"
        else:
            llm_response = message.get("content", "")

    return render(
        request,
        "archiver/enrich_archive.html",
        {"archive": archive, "llm_response": llm_response},
    )
