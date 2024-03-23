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



    
  default_apis = [
    "compute.googleapis.com",
    "bigquery.googleapis.com",
    "notebooks.googleapis.com",
    "bigquerystorage.googleapis.com"
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






