import utils.sla_validation as sla_validation

def test_full_sla():
    sla = {
        "application_name": "app",
        "application_namespace": "app",
        "service_name": "service",
        "service_namespace": "service"
    }

    assert sla_validation.valid_sla(sla) == True

    sla["application_name"] = "app-"
    assert sla_validation.valid_sla(sla) == False

    sla["application_name"] = "app"
    sla["application_namespace"] = "app_"
    assert sla_validation.valid_sla(sla) == False

    sla["application_namespace"] = "app"
    sla["service_name"] = "service!"
    assert sla_validation.valid_sla(sla) == False

    sla["service_name"] = "service"
    sla["service_namespace"] = "service."
    assert sla_validation.valid_sla(sla) == False

    sla["service_name"] = "service1234safasdf"
    sla["service_namespace"] = "servicfdfwefd"
    assert sla_validation.valid_sla(sla) == True

def test_sla_missing_field():
    sla = {
        "application_name": "app",
        "application_namespace": "app",
        "service_name": "service"
    }

    assert sla_validation.valid_sla(sla) == False

    sla = {
        "application_name": "app",
        "application_namespace": "app",
        "service_namespace": "service"
    }

    assert sla_validation.valid_sla(sla) == False

    sla = {
        "application_name": "app",
        "service_name": "service",
        "service_namespace": "service"
    }

    assert sla_validation.valid_sla(sla) == False

    sla = {
        "application_namespace": "app",
        "service_name": "service",
        "service_namespace": "service"
    }

    assert sla_validation.valid_sla(sla) == False