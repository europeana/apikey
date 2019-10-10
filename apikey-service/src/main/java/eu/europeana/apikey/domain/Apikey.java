/*
 * Copyright 2007-2017 The Europeana Foundation
 *
 *  Licenced under the EUPL, Version 1.1 (the "Licence") and subsequent versions as approved
 *  by the European Commission;
 *  You may not use this work except in compliance with the Licence.
 *
 *  You may obtain a copy of the Licence at:
 *  http://joinup.ec.europa.eu/software/page/eupl
 *
 *  Unless required by applicable law or agreed to in writing, software distributed under
 *  the Licence is distributed on an "AS IS" basis, without warranties or conditions of
 *  any kind, either express or implied.
 *  See the Licence for the specific language governing permissions and limitations under
 *  the Licence.
 */

/**
 * Created by luthien on 18/04/2017.
 */

package eu.europeana.apikey.domain;

import com.fasterxml.jackson.annotation.*;
import org.springframework.format.annotation.DateTimeFormat;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.util.Date;

import static eu.europeana.apikey.util.Tools.nvl;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Entity
@Table(name = "apikey")
public class Apikey {
	@Id
	@Column(name = "apikey")
	@JsonProperty("apikey")
	@JsonView(View.Public.class)
	private String apikey;

	@NotNull
	@Column(name = "keycloakid")
	@JsonProperty("keycloakid")
	@JsonIgnore
	private String keycloakId;

	@NotNull
	@Column(name = "registrationdate")
	@DateTimeFormat(iso = DateTimeFormat.ISO.DATE)
	@JsonProperty("registrationDate")
	@JsonView(View.Public.class)
	@JsonFormat(pattern="yyyy-MM-dd'T'HH:mm:ss'Z'")
	private Date registrationDate;

	@Size(max = 100)
	@Column(name = "website")
	@JsonProperty("website")
	@JsonView(View.Public.class)
	private String website;

	@Column(name = "activationdate")
	@DateTimeFormat(iso = DateTimeFormat.ISO.DATE)
	@JsonProperty("activationDate")
	@JsonView(View.Public.class)
	private Date activationDate;

	@NotNull
	@Size(max = 255)
	@Column(name = "appname")
	@JsonProperty("appName")
	@JsonView(View.Public.class)
	protected String appName;

	@NotNull
	@Size(max = 100)
	@Column(name = "company")
	@JsonProperty("company")
	@JsonView(View.Public.class)
	protected String company;

	@Size(max = 255)
	@Column(name = "sector")
	@JsonProperty("sector")
	@JsonView(View.Public.class)
	protected String sector;

	@NotNull
	@Size(max = 100)
	@Column(name = "email")
	@JsonProperty("email")
	@JsonView(View.Public.class)
	protected String email;

	@NotNull
	@Size(max = 50)
	@Column(name = "firstname")
	@JsonProperty("firstName")
	@JsonView(View.Public.class)
	protected String firstName;

	@NotNull
	@Size(max = 50)
	@Column(name = "lastname")
	@JsonProperty("lastName")
	@JsonView(View.Public.class)
	protected String lastName;

	@Column(name = "deprecationdate")
	@DateTimeFormat(iso = DateTimeFormat.ISO.DATE)
	@JsonProperty("deprecationDate")
	@JsonView(View.Public.class)
	private Date deprecationDate;

	@Column(name = "lastaccessdate")
	@DateTimeFormat(iso = DateTimeFormat.ISO.DATE)
	@JsonProperty("lastAccessDate")
	@JsonView(View.Public.class)
	private Date lastAccessDate;

	public Apikey() {

	}

	public Apikey(String apikey, String firstName, String lastName, String email, String appName, String company) {
		this.apikey = apikey;
		this.firstName = firstName;
		this.lastName = lastName;
		this.email = email;
		this.appName = appName;
		this.company = company;
		this.registrationDate = new Date();
	}

	public Apikey(Apikey copy) {
		this.apikey = copy.apikey;
		this.keycloakId = copy.keycloakId;
		this.registrationDate = copy.registrationDate;
		this.website = copy.website;
		this.activationDate = copy.activationDate;
		this.appName = copy.appName;
		this.company = copy.company;
		this.sector = copy.sector;
		this.email = copy.email;
		this.firstName = copy.firstName;
		this.lastName = copy.lastName;
		this.deprecationDate = copy.deprecationDate;
		this.lastAccessDate = copy.lastAccessDate;
	}

	public String getApikey() {
		return apikey;
	}

	public void setApikey(String apikey) {
		this.apikey = apikey;
	}

	@JsonIgnore
	public String getKeycloakId() {
		return keycloakId;
	}

	public void setKeycloakId(String keycloakId) {
		this.keycloakId = keycloakId;
	}

	public Date getRegistrationDate() {
		return registrationDate;
	}

	public void setRegistrationDate(Date registrationDate) {
		this.registrationDate = registrationDate;
	}

	public String getWebsite() {
		return website;
	}

	public void setWebsite(String website) {
		this.website = website;
	}

	public Date getActivationDate() {
		return activationDate;
	}

	public void setActivationDate(Date activationDate) {
		this.activationDate = activationDate;
	}

	public String getAppName() {
		return appName;
	}

	public void setAppName(String appName) {
		this.appName = appName;
	}

	public String getCompany() {
		return company;
	}

	public void setCompany(String company) {
		this.company = company;
	}

	public String getSector() {
		return sector;
	}

	public void setSector(String sector) {
		this.sector = sector;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getFirstName() {
		return firstName;
	}

	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}

	public String getLastName() {
		return lastName;
	}

	public void setLastName(String lastName) {
		this.lastName = lastName;
	}

	public Date getDeprecationDate() {
		return deprecationDate;
	}

	public void setDeprecationDate(Date deprecationDate) {
		this.deprecationDate = deprecationDate;
	}

	public Date getLastAccessDate() {
		return lastAccessDate;
	}

	public void setLastAccessDate(Date lastAccessDate) {
		this.lastAccessDate = lastAccessDate;
	}


	@Override
	public String toString() {
		return "Apikey {" +
				" apikey = " + apikey +
				", keycloakid = " + keycloakId +
				", firstName = " + nvl(firstName) +
				", lastName = " + nvl(lastName) +
				", email = " + nvl(email) +
				", appName = " + nvl(appName) +
				", website = " + nvl(website) +
				", company = " + nvl(company) +
				", sector = " + nvl(sector) +
				", activationDate = " + nvl(activationDate) +
				", registrationDate = " + nvl(registrationDate) +
				", lastAccessDate = " + nvl(lastAccessDate) +
				", deprecationDate = " + nvl(deprecationDate) +
				" }";
	}
}
