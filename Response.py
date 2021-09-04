def ConstructSuccess(data={}):
    return ConstructSkeleton('success', data)


def ConstructError(error_info, other_data={}):
    other_data['error_info'] = error_info
    return ConstructSkeleton('error', other_data)


def ConstructSkeleton(response_data: str, data_data: dict):
    return {
        'response': response_data,
        'data': data_data
    }
