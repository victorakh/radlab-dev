/**
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

locals {
  random_id = var.deployment_id != null ? var.deployment_id : random_id.default.0.hex
  project   = (var.create_project
  ? try(module.project_radlab_ds_analytics.0, null)
  : try(data.google_project.existing_project.0, null)
  )



  #hardcode Singapore to bypass the region/zone bug
  #region = join("-", [split("-", var.zone)[0], split("-", var.zone)[1]])
  region = "asia-southeast1"



  network = (
  var.create_network
  ? try(module.vpc_ai_notebook.0.network.network, null)
  : try(data.google_compute_network.default.0, null)
  )

  subnet = (
  var.create_network
  ? try(module.vpc_ai_notebook.0.subnets["${local.region}/${var.subnet_name}"], null)
  : try(data.google_compute_subnetwork.default.0, null)
  )

  notebook_sa_project_roles = [
    "roles/compute.instanceAdmin",
    "roles/notebooks.admin",
    "roles/bigquery.user",
    "roles/storage.admin",
    "roles/iam.serviceAccountUser",
    "roles/serviceusage.serviceUsageConsumer",
    "roles/monitoring.metricWriter",   //Amend - Add role for OS Agent monitoring
    "roles/logging.logWriter"          //Amend - Add role for OS Agent monitoring  
  ]

  default_apis = [
    "compute.googleapis.com",
    "bigquery.googleapis.com",
    "notebooks.googleapis.com",
    "bigquerystorage.googleapis.com",
    "logging.googleapis.com",     //Amend - Enable loggin API for OS Agent monitoring
    "monitoring.googleapis.com"    //Amend - Enable loggin API for OS Agent monitoring
  ]
  project_services = var.enable_services ? (var.billing_budget_pubsub_topic ? distinct(concat(local.default_apis,["pubsub.googleapis.com"])) : local.default_apis) : []
}

resource "random_id" "default" {
  count       = var.deployment_id == null ? 1 : 0
  byte_length = 2
}

#####################
# ANALYTICS PROJECT #
#####################

data "google_project" "existing_project" {
  count      = var.create_project ? 0 : 1
  project_id = var.project_id_prefix
}

module "project_radlab_ds_analytics" {
  count   = var.create_project ? 1 : 0
  source  = "terraform-google-modules/project-factory/google"
  version = "~> 13.0"

  name              = format("%s-%s", var.project_id_prefix, local.random_id)
  random_project_id = false
  folder_id         = var.folder_id
  billing_account   = var.billing_account_id
  org_id            = var.organization_id

  activate_apis = []
}

resource "google_project_service" "enabled_services" {
  for_each                   = toset(local.project_services)
  project                    = local.project.project_id
  service                    = each.value
  disable_dependent_services = true
  disable_on_destroy         = true

  depends_on = [
    module.project_radlab_ds_analytics
  ]
}

data "google_compute_network" "default" {
  count   = var.create_network ? 0 : 1
  project = local.project.project_id
  name    = var.network_name
}

data "google_compute_subnetwork" "default" {
  count   = var.create_network ? 0 : 1
  project = local.project.project_id
  name    = var.subnet_name
  region  = local.region
}

module "vpc_ai_notebook" {
  count   = var.create_network && var.create_usermanaged_notebook ? 1 : 0
  source  = "terraform-google-modules/network/google"
  version = "~> 5.0"

  project_id   = local.project.project_id
  network_name = var.network_name
  routing_mode = "GLOBAL"
  description  = "VPC Network created via Terraform"

  subnets = [
    {
      subnet_name           = var.subnet_name
      subnet_ip             = var.ip_cidr_range
      subnet_region         = local.region
      description           = "Subnetwork inside *vpc-analytics* VPC network, created via Terraform"
      subnet_private_access = true
    }
  ]

  firewall_rules = [
    {
      name        = "fw-ai-notebook-allow-internal"
      description = "Firewall rule to allow traffic on all ports inside *vpc-analytics* VPC network."
      priority    = 65534
      ranges      = ["10.0.0.0/8"]
      direction   = "INGRESS"

      allow = [
        {
          protocol = "tcp"
          ports    = ["0-65535"]
        }
      ]
    }
  ]

  depends_on = [
    module.project_radlab_ds_analytics,
    google_project_service.enabled_services,
    time_sleep.wait_120_seconds
  ]
}

resource "google_service_account" "sa_p_notebook" {
  project      = local.project.project_id
  account_id   = format("sa-p-notebook-%s", local.random_id)
  display_name = "Notebooks in trusted environment"
}

resource "google_project_iam_member" "sa_p_notebook_permissions" {
  for_each = toset(local.notebook_sa_project_roles)
  project  = local.project.project_id
  member   = "serviceAccount:${google_service_account.sa_p_notebook.email}"
  role     = each.value
}

resource "google_service_account_iam_member" "sa_ai_notebook_iam" {
  for_each           = toset(concat(formatlist("user:%s", var.trusted_users), formatlist("group:%s", var.trusted_groups)))
  member             = each.value
  role               = "roles/iam.serviceAccountUser"
  service_account_id = google_service_account.sa_p_notebook.id
}


# Amend - adding customer role to start and stop vm 
resource "google_project_iam_custom_role" "compute_start_stop_custom_role" {
  title = "compute_start_stop_custom_role"
  role_id     = "compute_start_stop_custom_role"
  description = "Allows starting and stopping Compute Engine VMs"
  project      = local.project.project_id
  permissions = [
    "compute.instances.start",
    "compute.instances.stop",
  ]
}

# Amend - assosicate start stop vm custom role with STE CDCS users group
resource "google_project_iam_member" "member_custom_role" {
  role    = google_project_iam_custom_role.compute_start_stop_custom_role.name
  member  = "group:rad-lab-users@gacteam.online"
  project = local.project.project_id
}


resource "null_resource" "ai_notebook_usermanaged_provisioning_state" {
  for_each = toset(google_notebooks_instance.ai_notebook_usermanaged[*].name)
  provisioner "local-exec" {
    #command = "while [ \"$(gcloud notebooks instances list --location ${var.zone} --project ${local.project.project_id} --filter 'NAME:${each.value} AND STATE:ACTIVE' --format 'value(STATE)' | wc -l | xargs)\" != 1 ]; do echo \"${each.value} not active yet.\"; done"
    #hardcode Singapore to bypass the region/zone bug
    command = "while [ \"$(gcloud notebooks instances list --location \"asia-southeast1-a\" --project ${local.project.project_id} --filter 'NAME:${each.value} AND STATE:ACTIVE' --format 'value(STATE)' | wc -l | xargs)\" != 1 ]; do echo \"${each.value} not active yet.\"; done"  
}

  depends_on = [google_notebooks_instance.ai_notebook_usermanaged]
}




resource "google_notebooks_instance" "ai_notebook_usermanaged" {
  count        = var.notebook_count > 0 && var.create_usermanaged_notebook ? var.notebook_count : 0
  project      = local.project.project_id
#  name         = "notebook-${count.index + 1}-${var.project_id_prefix}"        // Amend - usermanaged notebook name -  "notebook-1-projectname
  name         = "usermanaged-notebooks-${count.index + 1}"  // Original

#  name         = "notebook-${var.project_id_prefix}-${count.index + 1}"    // Amend - usermanaged notebook name -  "notebook-projectname-1"
  location     = "asia-southeast1-a"
  machine_type = var.machine_type

  dynamic "vm_image" {
    for_each = var.create_container_image ? [] : [1]
    content {
      project      = var.image_project
      image_family = var.image_family
    }
  }

  dynamic "container_image" {
    for_each = var.create_container_image ? [1] : []
    content {
      repository = var.container_image_repository
      tag        = var.container_image_tag
    }
  }

  install_gpu_driver = var.enable_gpu_driver

  dynamic "accelerator_config" {
    for_each = var.enable_gpu_driver ? [1] : []
    content {
      type       = var.gpu_accelerator_type
      core_count = var.gpu_accelerator_core_count
    }
  }

  service_account = google_service_account.sa_p_notebook.email

  boot_disk_type    = var.boot_disk_type
  boot_disk_size_gb = var.boot_disk_size_gb

  data_disk_type    = var.data_disk_type      //Amend - adding datadisk
  data_disk_size_gb = var.data_disk_size_gb   //Amend - adding datadisk

  tmp_disk_type    = var.tmp_disk_type      //Amend - adding tmp adisk for CIS hardening 1.1.2.1 Ensure /tmp is a separate partition
  tmp_disk_size_gb = tmp.tmp_disk_size_gb  //Amend - adding tmp adisk for CIS hardening 1.1.2.1 Ensure /tmp is a separate partition

  no_public_ip    = false
  no_proxy_access = false

  network = local.network.self_link
  subnet  = local.subnet.self_link

  post_startup_script = format("gs://%s/%s", google_storage_bucket.user_scripts_bucket.name, google_storage_bucket_object.notebook_post_startup_script.name)

  labels = {
    os     = "debian11"       //Amend - add new label
    module = "data-science"
  }

  metadata = {
    terraform  = "true"
    proxy-mode = "mail"
    report-system-health = "true"  //Amend-Update report-system-health=TRUE
  }
  depends_on = [
    time_sleep.wait_120_seconds,
    google_storage_bucket_object.notebooks
  ]
}

resource "google_notebooks_runtime" "ai_notebook_googlemanaged" {
  count    = var.notebook_count > 0 && !var.create_usermanaged_notebook ? var.notebook_count : 0
  name     = "googlemanaged-notebooks-${count.index + 1}"
  project  = local.project.project_id
  location = local.region
  access_config {
    access_type   = "SERVICE_ACCOUNT"
    runtime_owner = google_service_account.sa_p_notebook.email
  }

 software_config {
    post_startup_script          = format("gs://%s/%s", google_storage_bucket.user_scripts_bucket.name, google_storage_bucket_object.notebook_post_startup_script.name)
    post_startup_script_behavior = "RUN_EVERY_START"
 }



  virtual_machine {
    virtual_machine_config {
      machine_type = var.machine_type
      dynamic "container_images" {
        for_each = var.create_container_image ? [1] : []
        content {
          repository = var.container_image_repository
          tag        = var.container_image_tag
        }
      }
      data_disk {
        initialize_params {
          disk_size_gb = var.boot_disk_size_gb
          disk_type    = var.boot_disk_type
        }
      }
      dynamic "accelerator_config" {
        for_each = var.enable_gpu_driver ? [1] : []
        content {
          type       = var.gpu_accelerator_type
          core_count = var.gpu_accelerator_core_count
        }
      }
    }
  }
  depends_on = [
    time_sleep.wait_120_seconds,
    google_storage_bucket_object.notebooks
  ]
}

resource "google_storage_bucket" "user_scripts_bucket" {
  project                     = local.project.project_id
  name                        = join("", ["user-scripts-", local.project.project_id])
  location                    = local.region
  force_destroy               = true
  uniform_bucket_level_access = true

  cors {
    origin          = ["http://user-scripts"]
    method          = ["GET", "HEAD", "PUT", "POST", "DELETE"]
    response_header = ["*"]
    max_age_seconds = 3600
  }
}

resource "google_storage_bucket_iam_binding" "binding" {
  bucket  = google_storage_bucket.user_scripts_bucket.name
  role    = "roles/storage.admin"
  members = toset(concat(formatlist("user:%s", var.trusted_users), formatlist("group:%s", var.trusted_groups)))
}



## Modification starts here  

# Create Cloud Storage bucket
resource "google_storage_bucket" "notebook_bucket" {
  project                     = local.project.project_id
  name                        = format("%s-%s", var.bucket_id_prefix, local.random_id)
  location                    = local.region
  force_destroy               = true
  uniform_bucket_level_access = true
}

# Create Cloud Storage bucket IAM binding
resource "google_storage_bucket_iam_binding" "notebook_bucket_binding" {
  bucket  = google_storage_bucket.notebook_bucket.name
  role    = "roles/storage.admin"
  members = toset(concat(formatlist("user:%s", var.trusted_users), formatlist("group:%s", var.trusted_groups)))
}


# Enable VM Manager service
resource "google_project_service" "vm_manager" {
  project = local.project.project_id
  service = "osconfig.googleapis.com"  # Service name for VM Manager
}


resource "google_compute_project_metadata_item" "enable-osconfig" {
  project = local.project.project_id
  key     = "enable-osconfig"
  value   = "TRUE"
}


# Monthly OS Patch on 28th at 10pm SGT 
resource "google_os_config_patch_deployment" "monthly_patch_debian" {
  project = local.project.project_id
  patch_deployment_id = "monthly-patch-debian"

   instance_filter {
    group_labels {
      labels = {
    		os     = "debian11"
       module  = "data-science"
      }
    }
    
    zones = ["asia-southeast1-a", "asia-southeast1-b"]   
   }

  patch_config {
    reboot_config = "DEFAULT" # System will be rebooting only if required

    apt {
      type = "UPGRADE"
    }
  }
  duration = "1800s"


  recurring_schedule {
    time_zone {
      id = "Asia/Singapore"
    }

    time_of_day {
      hours = 22
      minutes = 0
    }

    monthly {
      month_day = 28
    }
  }
}


