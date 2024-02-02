from django.http import JsonResponse


def index(request):
    data = {
        'key1': 'value1',
    }
    response = JsonResponse(data, status=200)
    return response
