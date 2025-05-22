/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package software.amazon.jdbc.authentication;

import java.nio.file.Paths;
import java.util.Properties;
import java.util.concurrent.locks.ReentrantLock;
import org.checkerframework.checker.nullness.qual.Nullable;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.ProfileProviderCredentialsContext;
import software.amazon.awssdk.profiles.Profile;
import software.amazon.awssdk.profiles.ProfileFile;
import software.amazon.awssdk.services.sso.auth.SsoProfileCredentialsProviderFactory;
import software.amazon.jdbc.HostSpec;
import software.amazon.jdbc.PropertyDefinition;
import software.amazon.jdbc.util.StringUtils;

public class AwsCredentialsManager {
  private static AwsCredentialsProviderHandler handler = null;

  private static final ReentrantLock lock = new ReentrantLock();

  public static void setCustomHandler(final AwsCredentialsProviderHandler customHandler) {
    lock.lock();
    try {
      handler = customHandler;
    } finally {
      lock.unlock();
    }
  }

  public static void resetCustomHandler() {
    lock.lock();
    try {
      handler = null;
    } finally {
      lock.unlock();
    }
  }

  public static AwsCredentialsProvider getProvider(final HostSpec hostSpec, final Properties props) {
    lock.lock();
    try {
      AwsCredentialsProvider provider = handler == null
          ? null
          : handler.getAwsCredentialsProvider(hostSpec, props);

      if (provider == null) {
        provider =
            getDefaultProvider(
                PropertyDefinition.AWS_PROFILE.getString(props),
                PropertyDefinition.AWS_SSO.getBoolean(props)
            );
      }

      return provider;
    } finally {
      lock.unlock();
    }
  }

  private static AwsCredentialsProvider getDefaultProvider(
      final @Nullable String awsProfileName, final boolean useSso) {
    if (useSso) {
      // Load shared AWS config (~/.aws/config)
      ProfileFile profileFile = ProfileFile.defaultProfileFile();
      Profile profile = profileFile.profile(awsProfileName)
          .orElseThrow(() -> new IllegalArgumentException("Profile not found: " + awsProfileName));
      ProfileProviderCredentialsContext profileProvider =
          ProfileProviderCredentialsContext.builder()
              .profile(profile)
              .profileFile(profileFile)
              .build();
      SsoProfileCredentialsProviderFactory factory = new SsoProfileCredentialsProviderFactory();
      return factory.create(profileProvider);
    } else {
      DefaultCredentialsProvider.Builder builder = DefaultCredentialsProvider.builder();
      if (!StringUtils.isNullOrEmpty(awsProfileName)) {
        builder.profileName(awsProfileName);
      }
      return builder.build();
    }
  }
}
