import geoip2.database

reader = geoip2.database.Reader('GeoLite2-City.mmdb')

def get_location(ip):
    try:
        response = reader.city(ip)
        return response.country.name
    except:
        return "Unknown"